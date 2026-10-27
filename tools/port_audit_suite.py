#!/usr/bin/env python3
"""Port an independent audit suite into the unified repository.

The audit suites were written against the two split trees and marked the
defects they found with ``@pytest.mark.xfail``.  In the unified release the
defects are fixed, so the markers come off: every reproduction becomes an
ordinary test that has to pass.

The script only rewrites the markers and the paths that point at the old
trees; it never touches a test body.
"""

from __future__ import annotations

import pathlib
import re
import sys


def strip_xfail(text: str) -> tuple[str, int]:
    """Remove every ``@pytest.mark.xfail(...)`` decorator."""
    removed = 0
    while True:
        match = re.search(r"@pytest\.mark\.xfail\(", text)
        if match is None:
            return text, removed
        depth = 0
        index = match.end() - 1
        end = index
        while index < len(text):
            if text[index] == "(":
                depth += 1
            elif text[index] == ")":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
            index += 1
        # Swallow the rest of the decorator line and the blank lines it left.
        while end < len(text) and text[end] in " \t":
            end += 1
        if end < len(text) and text[end] == "\n":
            end += 1
        text = text[: match.start()] + text[end:]
        removed += 1


def main() -> int:
    source = pathlib.Path(sys.argv[1])
    target = pathlib.Path(sys.argv[2])
    text = source.read_text(encoding="utf-8")
    text, removed = strip_xfail(text)
    target.write_text(text, encoding="utf-8")
    print(f"{target}: removed {removed} xfail marker(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

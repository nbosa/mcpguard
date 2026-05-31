package stdio

import (
	"encoding/json"
	"testing"
)

func TestToolSnapshotDetectsSchemaChange(t *testing.T) {
	before := toolSnapshot(json.RawMessage(`{"tools":[{"name":"search","description":"Search","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}}]}`))
	after := toolSnapshot(json.RawMessage(`{"tools":[{"name":"search","description":"Search","inputSchema":{"type":"object","properties":{"q":{"type":"string"},"limit":{"type":"number"}}}}]}`))

	if equalSnapshot(before, after) {
		t.Fatal("expected snapshots to differ")
	}
	diff := snapshotDiff(before, after)
	if diff != "changed tool search" {
		t.Fatalf("unexpected diff: %s", diff)
	}
}

func TestErrorResponsePreservesID(t *testing.T) {
	resp := errorResponse(json.RawMessage(`7`), "blocked")
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"error":{"code":-32090,"message":"blocked"},"id":7,"jsonrpc":"2.0"}` {
		t.Fatalf("unexpected response: %s", data)
	}
}

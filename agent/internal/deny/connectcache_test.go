package deny

import (
	"testing"
)

func TestConnectCacheRecordLookupForget(t *testing.T) {
	c := NewConnectCache()
	c.Record(1, "10.0.0.1", 443)
	ip, port, ok := c.Lookup(1)
	if !ok || ip != "10.0.0.1" || port != 443 {
		t.Fatalf("lookup=%q:%d ok=%v", ip, port, ok)
	}
	c.Forget(1)
	if _, _, ok := c.Lookup(1); ok {
		t.Fatal("expected miss after forget")
	}
}

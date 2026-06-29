package policy

import (
	"testing"
	"time"
)

func TestStorePutGetListCurrent(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte(validBundle)
	sig := []byte("fake-sig")
	b, err := Parse(bundle)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(b)
	if err != nil {
		t.Fatal(err)
	}
	meta := VersionMeta{
		Version:    1,
		SignedBy:   "test",
		AgentScope: "agent:test",
		LoadedAt:   time.Now().UTC(),
		Verified:   true,
		State:      StateEnforced,
	}
	if err := store.Put(meta, bundle, sig, compiled); err != nil {
		t.Fatal(err)
	}
	if err := store.SetCurrent(1); err != nil {
		t.Fatal(err)
	}
	cur, err := store.Current()
	if err != nil || cur != 1 {
		t.Fatalf("current=%d err=%v", cur, err)
	}
	list, err := store.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("list=%v err=%v", list, err)
	}
	stored, err := store.Get(1)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Compiled == nil || len(stored.Compiled.Live) != 1 {
		t.Fatalf("compiled missing: %+v", stored.Compiled)
	}
}

func TestStoreRollback(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ver := range []int{1, 2} {
		meta := VersionMeta{Version: ver, SignedBy: "test", AgentScope: "agent:test", State: StateEnforced}
		if err := store.Put(meta, []byte(validBundle), []byte("sig"), nil); err != nil {
			t.Fatal(err)
		}
	}
	loader := &Loader{Store: store}
	if err := loader.Rollback(1); err != nil {
		t.Fatal(err)
	}
	cur, _ := store.Current()
	if cur != 1 {
		t.Fatalf("current=%d want 1", cur)
	}
}

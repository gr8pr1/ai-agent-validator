package feedback

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecentFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feedback.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now()
	d1 := NewDecision(at, 10, "open", "/etc/shadow", "agent", "r1", "no", 1)
	d2 := NewDecision(at.Add(time.Millisecond), 20, "connect", "", "agent", "r2", "egress", 1)
	for _, d := range []Decision{d1, d2} {
		b, _ := json.Marshal(d)
		f.Write(b)
		f.Write([]byte{'\n'})
	}
	f.Close()

	got, err := RecentFromFile(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].PID != 20 {
		t.Fatalf("got=%+v", got)
	}
}

func TestFindForPIDFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "feedback.jsonl")
	hub, err := NewHub(path, 8)
	if err != nil {
		t.Fatal(err)
	}
	since := time.Now()
	go func() {
		time.Sleep(30 * time.Millisecond)
		hub.Record(NewDecision(time.Now(), 4242, "open", "/etc/shadow", "agent", "deny-shadow", "blocked", 1))
	}()

	got, err := FindForPID(LookupConfig{File: path, Wait: 200 * time.Millisecond}, 4242, since)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.MatchedRule != "deny-shadow" {
		t.Fatalf("got=%+v", got)
	}
}

func TestFromHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]Decision{
			NewDecision(time.Now(), 7, "open", "/x", "agent", "r", "reason", 1),
		})
	}))
	defer srv.Close()

	got, err := FromHTTP(srv.URL, "agent", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PID != 7 {
		t.Fatalf("got=%+v", got)
	}
}

func TestShimLine(t *testing.T) {
	d := NewDecision(time.Now(), 1, "open", "/etc/shadow", "agent", "r", "x", 1)
	line := d.ShimLine()
	if len(line) <= len(ShimPrefix) || line[:len(ShimPrefix)] != ShimPrefix {
		t.Fatalf("line=%q", line)
	}
}

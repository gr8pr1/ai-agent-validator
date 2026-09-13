package deny

import (
	"net"
	"testing"
)

func TestFormatConnectTargetIPv4(t *testing.T) {
	got := FormatConnectTarget("8.8.8.8", 443)
	if got != "8.8.8.8:443" {
		t.Fatalf("got=%q", got)
	}
	host, port, err := net.SplitHostPort(got)
	if err != nil || host != "8.8.8.8" || port != "443" {
		t.Fatalf("split=%q %q err=%v", host, port, err)
	}
}

func TestFormatConnectTargetIPv6(t *testing.T) {
	got := FormatConnectTarget("2001:db8::1", 443)
	host, port, err := net.SplitHostPort(got)
	if err != nil || host != "2001:db8::1" || port != "443" {
		t.Fatalf("got=%q split=%q %q err=%v", got, host, port, err)
	}
}

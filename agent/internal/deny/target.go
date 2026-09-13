package deny

import (
	"fmt"
	"net"
	"strconv"
)

// FormatConnectTarget renders ip:port for policy feedback (architecture §5.6).
func FormatConnectTarget(ip string, port uint16) string {
	if ip == "" {
		return ""
	}
	if port == 0 {
		return ip
	}
	return net.JoinHostPort(ip, strconv.Itoa(int(port)))
}

func parseDestIP(family uint8, raw []byte) string {
	switch family {
	case 2: // AF_INET
		if len(raw) < 4 {
			return ""
		}
		return fmt.Sprintf("%d.%d.%d.%d", raw[0], raw[1], raw[2], raw[3])
	case 10: // AF_INET6
		if len(raw) < 16 {
			return ""
		}
		return net.IP(raw[:16]).String()
	default:
		return ""
	}
}

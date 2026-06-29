// Package event decodes the fixed-layout records emitted by the enrollment BPF
// program (bpf/enroll.bpf.c) over the ringbuf.
package event

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Layout constants. These MUST stay in sync with struct enroll_event and the
// EVENT_* / MAX_* defines in bpf/enroll.bpf.c.
const (
	HeaderSize       = 64
	MaxFilename      = 256
	MaxArgv          = 512
	MaxEnv           = 512
	RecordSize       = HeaderSize + MaxFilename + MaxArgv + MaxEnv
	ActionDetailSize = 24
	MaxPath          = 256
	ActionRecordSize = HeaderSize + ActionDetailSize + MaxPath + MaxPath
	AFINET           = 2
	AFINET6          = 10
	oWRONLY          = 1
	oRDWR            = 2
	oCREAT           = 64
	oTRUNC           = 512
	filenameOff      = HeaderSize
	argvOff          = HeaderSize + MaxFilename
	envOff           = HeaderSize + MaxFilename + MaxArgv
	actionDetailOff  = HeaderSize
	actionPathOff    = HeaderSize + ActionDetailSize
	actionPath2Off   = HeaderSize + ActionDetailSize + MaxPath
)

// Event types, mirroring the BPF EVENT_* defines.
const (
	TypeExec    uint8 = 1
	TypeFork    uint8 = 2
	TypeExit    uint8 = 3
	TypeConnect uint8 = 4
	TypeOpen    uint8 = 5
	TypeUnlink  uint8 = 6
	TypeRename  uint8 = 7
)

// Event is a decoded process-lifecycle or action record.
type Event struct {
	TimestampNs uint64
	StartTimeNs uint64
	CgroupID    uint64
	PID         uint32
	PPID        uint32
	UID         uint32
	Type        uint8
	Comm        string
	Filename    string   // exec only: resolved binary path
	Argv        []string // exec only: bounded prefix
	Env         []string // exec only: bounded prefix, raw KEY=VALUE entries
	// Action fields (connect/open/unlink/rename).
	Family    uint8
	DestIP    string
	DestPort  uint16
	OpenFlags uint32
	Path      string
	Path2     string
}

// TypeString returns a short human label for the event type.
func (e *Event) TypeString() string {
	switch e.Type {
	case TypeExec:
		return "exec"
	case TypeFork:
		return "fork"
	case TypeExit:
		return "exit"
	case TypeConnect:
		return "connect"
	case TypeOpen:
		return "open"
	case TypeUnlink:
		return "unlink"
	case TypeRename:
		return "rename"
	default:
		return "unknown"
	}
}

// IsOpenWriteIntent reports whether open flags indicate write/create/truncate intent.
func IsOpenWriteIntent(flags uint32) bool {
	mode := flags & 3
	if mode == oWRONLY || mode == oRDWR {
		return true
	}
	return flags&oCREAT != 0 || flags&oTRUNC != 0
}

// ErrShort is returned when a ringbuf record is smaller than the fixed header.
var ErrShort = errors.New("event: record shorter than header")

// Parse decodes one ringbuf record.
func Parse(data []byte) (*Event, error) {
	if len(data) < HeaderSize {
		return nil, ErrShort
	}
	e := &Event{
		TimestampNs: binary.LittleEndian.Uint64(data[0:8]),
		StartTimeNs: binary.LittleEndian.Uint64(data[8:16]),
		CgroupID:    binary.LittleEndian.Uint64(data[16:24]),
		PID:         binary.LittleEndian.Uint32(data[24:28]),
		PPID:        binary.LittleEndian.Uint32(data[28:32]),
		UID:         binary.LittleEndian.Uint32(data[32:36]),
		Type:        data[36],
	}
	pathLen := int(binary.LittleEndian.Uint16(data[38:40]))
	path2Len := int(binary.LittleEndian.Uint16(data[40:42]))
	fnLen := int(binary.LittleEndian.Uint16(data[42:44]))
	e.Comm = cstr(data[44:60])

	switch e.Type {
	case TypeExec:
		if len(data) < RecordSize {
			return nil, ErrShort
		}
		e.Filename = sliceStr(data, filenameOff, fnLen, MaxFilename)
		e.Argv = splitNul(sliceBytes(data, argvOff, pathLen, MaxArgv))
		e.Env = splitNul(sliceBytes(data, envOff, path2Len, MaxEnv))
	case TypeConnect, TypeOpen, TypeUnlink, TypeRename:
		if len(data) < ActionRecordSize {
			return nil, ErrShort
		}
		parseAction(e, data, pathLen, path2Len)
	default:
		// fork/exit: header only
		_ = fnLen
	}
	return e, nil
}

func parseAction(e *Event, data []byte, pathLen, path2Len int) {
	detail := data[actionDetailOff : actionDetailOff+ActionDetailSize]
	e.Family = detail[0]
	e.DestPort = binary.LittleEndian.Uint16(detail[2:4])
	e.OpenFlags = binary.LittleEndian.Uint32(detail[4:8])
	addr := detail[8:24]
	e.DestIP = formatAddr(e.Family, addr)
	e.Path = sliceStr(data, actionPathOff, pathLen, MaxPath)
	e.Path2 = sliceStr(data, actionPath2Off, path2Len, MaxPath)
}

func formatAddr(family uint8, addr []byte) string {
	switch family {
	case AFINET:
		if len(addr) < 4 {
			return ""
		}
		return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
	case AFINET6:
		if len(addr) < 16 {
			return ""
		}
		return net.IP(addr[:16]).String()
	default:
		return ""
	}
}

func sliceBytes(data []byte, off, n, max int) []byte {
	if n <= 0 {
		return nil
	}
	if n > max {
		n = max
	}
	end := off + n
	if end > len(data) {
		return nil
	}
	return data[off:end]
}

func sliceStr(data []byte, off, n, max int) string {
	return cstr(sliceBytes(data, off, n, max))
}

// cstr trims at the first NUL.
func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// splitNul splits a NUL-separated blob into non-empty strings.
func splitNul(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	var out []string
	start := 0
	for i, c := range b {
		if c == 0 {
			if i > start {
				out = append(out, string(b[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}

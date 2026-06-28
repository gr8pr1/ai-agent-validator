// Package event decodes the fixed-layout records emitted by the enrollment BPF
// program (bpf/enroll.bpf.c) over the ringbuf.
package event

import (
	"encoding/binary"
	"errors"
)

// Layout constants. These MUST stay in sync with struct enroll_event and the
// EVENT_* / MAX_* defines in bpf/enroll.bpf.c.
const (
	HeaderSize  = 64
	MaxFilename = 256
	MaxArgv     = 512
	MaxEnv      = 512
	RecordSize  = HeaderSize + MaxFilename + MaxArgv + MaxEnv

	filenameOff = HeaderSize
	argvOff     = HeaderSize + MaxFilename
	envOff      = HeaderSize + MaxFilename + MaxArgv
)

// Event types, mirroring the BPF EVENT_* defines.
const (
	TypeExec uint8 = 1
	TypeFork uint8 = 2
	TypeExit uint8 = 3
)

// Event is a decoded process-lifecycle record.
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
	default:
		return "unknown"
	}
}

// ErrShort is returned when a ringbuf record is smaller than the fixed header.
var ErrShort = errors.New("event: record shorter than header")

// Parse decodes one ringbuf record. Fork/exit records are header-only;
// exec records carry the fixed-size tail with filename/argv/env regions.
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
	argvLen := int(binary.LittleEndian.Uint16(data[38:40]))
	envLen := int(binary.LittleEndian.Uint16(data[40:42]))
	fnLen := int(binary.LittleEndian.Uint16(data[42:44]))
	e.Comm = cstr(data[44:60])

	if e.Type != TypeExec {
		return e, nil
	}
	e.Filename = sliceStr(data, filenameOff, fnLen, MaxFilename)
	e.Argv = splitNul(sliceBytes(data, argvOff, argvLen, MaxArgv))
	e.Env = splitNul(sliceBytes(data, envOff, envLen, MaxEnv))
	return e, nil
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

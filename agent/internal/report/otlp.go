package report

// OTLP export is a planned sink for the enrollment/observation stream, aligned
// with the OTLP path in ebpf-host-monitor. It is intentionally inert in P0 to
// keep the dependency surface minimal; the seam exists so the pipeline can fan
// out to it later without restructuring.
//
// When implemented, OTLPSink will satisfy the same Emit(Record) contract and be
// registered alongside the stdout/audit sinks behind an off-by-default config
// flag.
type OTLPSink struct {
	enabled bool
}

// Enabled reports whether OTLP export is active (always false in P0).
func (s *OTLPSink) Enabled() bool { return s != nil && s.enabled }

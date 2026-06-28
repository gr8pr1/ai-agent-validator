// Package debugsrv exposes a small read-only HTTP surface for inspecting P0
// state: live tagged process trees, the loaded fingerprint set, and counters.
package debugsrv

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/enroll"
)

// Server serves debug endpoints backed by the enrollment engine.
type Server struct {
	eng *enroll.Engine
	log *slog.Logger
}

func New(eng *enroll.Engine, log *slog.Logger) *Server {
	return &Server{eng: eng, log: log}
}

// Start launches the HTTP server in a goroutine. It returns the *http.Server so
// the caller can shut it down.
func (s *Server) Start(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/agents", s.handleAgents)
	mux.HandleFunc("/debug/fingerprints", s.handleFingerprints)
	mux.HandleFunc("/debug/stats", s.handleStats)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error("debug server", "err", err)
		}
	}()
	s.log.Info("debug server listening", "addr", addr)
	return srv
}

func (s *Server) handleAgents(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.eng.Table().TaggedSnapshot())
}

func (s *Server) handleFingerprints(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.eng.Fingerprints())
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	total, enrollments, agents := s.eng.Stats().Snapshot()
	writeJSON(w, map[string]any{
		"total_events": total,
		"enrollments":  enrollments,
		"agents":       agents,
		"tracked_pids": s.eng.Table().Len(),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// Command shim wraps subprocess execution and surfaces policy feedback when the
// host enforcer blocks an action (architecture §5.6 P4.2).
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/feedback"
)

func main() {
	var (
		feedbackFile = flag.String("feedback-file", envOr("AIBLOCKER_FEEDBACK_FILE", ""), "JSONL path written by agent feedback.path")
		feedbackURL  = flag.String("feedback-url", envOr("AIBLOCKER_FEEDBACK_URL", ""), "agent debug URL, e.g. http://127.0.0.1:9230/debug/feedback")
		agentID      = flag.String("agent-id", envOr("AIBLOCKER_AGENT_ID", ""), "agent_id for HTTP lookup")
		waitMS       = flag.Int("wait-ms", 500, "max wait for feedback after command failure")
		quiet        = flag.Bool("quiet", false, "omit human-readable stderr message")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] -- <command> [args...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	start := time.Now()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		sig, ok := <-sigCh
		if !ok || cmd.Process == nil {
			return
		}
		_ = syscall.Kill(-cmd.Process.Pid, sig.(syscall.Signal))
	}()

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			fmt.Fprintf(os.Stderr, "shim: %v\n", err)
			exitCode = 1
		}
	}

	file := strings.TrimSpace(*feedbackFile)
	url := strings.TrimSpace(*feedbackURL)
	if exitCode != 0 && cmd.Process != nil && (file != "" || url != "") {
		cfg := feedback.LookupConfig{
			File:    file,
			URL:     url,
			AgentID: strings.TrimSpace(*agentID),
			Wait:    time.Duration(*waitMS) * time.Millisecond,
		}
		pid := uint32(cmd.Process.Pid) //nolint:gosec // pid fits uint32
		d, lookupErr := feedback.FindForPID(cfg, pid, start)
		if d != nil {
			fmt.Fprintln(os.Stderr, d.ShimLine())
			if !*quiet {
				fmt.Fprintln(os.Stderr, d.HumanMessage())
			}
		} else if lookupErr != nil {
			fmt.Fprintf(os.Stderr, "shim: feedback lookup: %v\n", lookupErr)
		}
	}
	os.Exit(exitCode)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

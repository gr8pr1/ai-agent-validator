// Command policyctl is the P1 trusted policy loader CLI.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/gr8pr1/ebpf-ai-blocker/agent/internal/policy"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "sign":
		err = cmdSign(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "compile":
		err = cmdCompile(os.Args[2:])
	case "load":
		err = cmdLoad(os.Args[2:])
	case "history":
		err = cmdHistory(os.Args[2:])
	case "rollback":
		err = cmdRollback(os.Args[2:])
	case "show":
		err = cmdShow(os.Args[2:])
	case "shadow-report":
		err = cmdShadowReport(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `policyctl — P1 policy loader

Usage:
  policyctl keygen [--key policy.key] [--pub policy.pub]
  policyctl sign [--key policy.key] <bundle.yaml>
  policyctl verify [--pub policy.pub] <bundle.yaml>
  policyctl compile <bundle.yaml>
  policyctl load [--pub policy.pub] [--store ./policy-store] <bundle.yaml>
  policyctl history [--store ./policy-store]
  policyctl rollback [--store ./policy-store] <version>
  policyctl show [--store ./policy-store] [version]
  policyctl shadow-report [--audit PATH] [--since DURATION]

Flags must appear before positional arguments.

// TODO (future, decision 8B): policyctl promote <rule-id> — flip rule state in bundle YAML.

`)
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	keyPath := fs.String("key", "policy.key", "private key path")
	pubPath := fs.String("pub", "policy.pub", "public key path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, err := policy.Keygen(*keyPath, *pubPath)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s\n", *keyPath, *pubPath)
	return nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "policy.key", "private key path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: policyctl sign <bundle.yaml>")
	}
	priv, err := policy.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	if err := policy.SignFile(fs.Arg(0), priv); err != nil {
		return err
	}
	fmt.Printf("signed %s → %s\n", fs.Arg(0), policy.SigPath(fs.Arg(0)))
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pub", "policy.pub", "public key path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: policyctl verify <bundle.yaml>")
	}
	pub, err := policy.LoadPublicKey(*pubPath)
	if err != nil {
		return err
	}
	if err := policy.VerifyFile(fs.Arg(0), pub); err != nil {
		return err
	}
	fmt.Println("signature OK")
	return nil
}

func cmdCompile(args []string) error {
	fs := flag.NewFlagSet("compile", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: policyctl compile <bundle.yaml>")
	}
	b, err := policy.Load(fs.Arg(0))
	if err != nil {
		return err
	}
	compiled, err := policy.Compile(b)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(compiled)
}

func cmdLoad(args []string) error {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	pubPath := fs.String("pub", "policy.pub", "public key path")
	storePath := fs.String("store", "./policy-store", "version store directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: policyctl load <bundle.yaml>")
	}
	pub, err := policy.LoadPublicKey(*pubPath)
	if err != nil {
		return err
	}
	store, err := policy.OpenStore(*storePath)
	if err != nil {
		return err
	}
	loader := &policy.Loader{Store: store, PubKey: pub}
	res, err := loader.Load(policy.FileSource{BundlePath: fs.Arg(0)})
	if err != nil {
		return err
	}
	fmt.Printf("loaded version %d (agent_scope=%q, live_rules=%d, shadow_rules=%d)\n",
		res.Meta.Version, res.Meta.AgentScope, len(res.Compiled.Live), len(res.Compiled.Shadow))
	return nil
}

func cmdHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	storePath := fs.String("store", "./policy-store", "version store directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := policy.OpenStore(*storePath)
	if err != nil {
		return err
	}
	list, err := store.List()
	if err != nil {
		return err
	}
	cur, _ := store.Current()
	if len(list) == 0 {
		fmt.Println("no versions stored")
		return nil
	}
	for _, m := range list {
		marker := ""
		if m.Version == cur {
			marker = " (current)"
		}
		fmt.Printf("v%d  scope=%q  signed_by=%q  sha256=%s%s\n",
			m.Version, m.AgentScope, m.SignedBy, m.BundleSHA256[:12], marker)
	}
	return nil
}

func cmdRollback(args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ExitOnError)
	storePath := fs.String("store", "./policy-store", "version store directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: policyctl rollback <version>")
	}
	ver, err := strconv.Atoi(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("invalid version: %w", err)
	}
	store, err := policy.OpenStore(*storePath)
	if err != nil {
		return err
	}
	loader := &policy.Loader{Store: store}
	if err := loader.Rollback(ver); err != nil {
		return err
	}
	fmt.Printf("rolled back to version %d\n", ver)
	return nil
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	storePath := fs.String("store", "./policy-store", "version store directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := policy.OpenStore(*storePath)
	if err != nil {
		return err
	}
	ver := 0
	if fs.NArg() > 0 {
		ver, err = strconv.Atoi(fs.Arg(0))
		if err != nil {
			return fmt.Errorf("invalid version: %w", err)
		}
	} else {
		ver, err = store.Current()
		if err != nil {
			return err
		}
		if ver == 0 {
			return fmt.Errorf("no current version; specify a version number")
		}
	}
	stored, err := store.Get(ver)
	if err != nil {
		return err
	}
	if stored.Compiled == nil {
		b, err := policy.Parse(stored.Bundle)
		if err != nil {
			return err
		}
		stored.Compiled, err = policy.Compile(b)
		if err != nil {
			return err
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(stored.Compiled); err != nil {
		return err
	}
	return nil
}

func cmdShadowReport(args []string) error {
	fs := flag.NewFlagSet("shadow-report", flag.ExitOnError)
	auditPath := fs.String("audit", "audit.jsonl", "audit log JSONL path")
	sinceDur := fs.String("since", "", "only count events after this duration ago (e.g. 24h, 168h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var since time.Time
	if *sinceDur != "" {
		d, err := time.ParseDuration(*sinceDur)
		if err != nil {
			return fmt.Errorf("invalid --since duration: %w", err)
		}
		since = time.Now().Add(-d)
	}
	rows, err := policy.ShadowReport(*auditPath, since)
	if err != nil {
		return err
	}
	fmt.Print(policy.FormatShadowReport(rows))
	return nil
}

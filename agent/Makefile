.PHONY: all bpf build build-policyctl test vet clean run policy-test

CLANG       ?= $(shell which clang 2>/dev/null || echo /usr/bin/clang)
BPF_INCLUDE ?= $(shell if [ -d /usr/include/bpf ]; then echo "-I/usr/include"; elif [ -d /usr/local/include/bpf ]; then echo "-I/usr/local/include"; fi)
BPF_CFLAGS  ?= -O2 -g -Wall -target bpf $(BPF_INCLUDE)
BINARY      ?= aiblocker-agent
POLICYCTL   ?= policyctl

all: bpf build build-policyctl

# Compile eBPF objects and stage them for go:embed.
bpf:
	cd bpf && $(CLANG) $(BPF_CFLAGS) -c enroll.bpf.c -o enroll.bpf.o
	cd bpf && $(CLANG) $(BPF_CFLAGS) -c enforcer.bpf.c -o enforcer.bpf.o
	mkdir -p cmd/agent/bpf
	cp bpf/enroll.bpf.o cmd/agent/bpf/
	cp bpf/enforcer.bpf.o cmd/agent/bpf/

build:
	go build -o $(BINARY) ./cmd/agent

build-policyctl:
	go build -o $(POLICYCTL) ./cmd/policyctl

test:
	go test ./...

vet:
	go vet ./...

policy-test: build-policyctl
	./scripts/policy-test.sh

# Needs root/CAP_BPF for eBPF load + attach.
run: all
	sudo ./$(BINARY) --config config.yaml

clean:
	rm -f $(BINARY) $(POLICYCTL)
	rm -f bpf/enroll.bpf.o bpf/enforcer.bpf.o
	rm -f cmd/agent/bpf/enroll.bpf.o cmd/agent/bpf/enforcer.bpf.o

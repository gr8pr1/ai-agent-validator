.PHONY: all bpf build build-policyctl build-shim test vet clean run policy-test

CLANG       ?= $(shell which clang 2>/dev/null || echo /usr/bin/clang)
UNAME_M     := $(shell uname -m)
BPF_INCLUDE ?= $(shell if [ -d /usr/include/bpf ]; then echo "-I/usr/include"; elif [ -d /usr/local/include/bpf ]; then echo "-I/usr/local/include"; fi)
ifeq ($(UNAME_M),x86_64)
BPF_ARCH_CFLAGS := -D__TARGET_ARCH_x86
else ifeq ($(UNAME_M),aarch64)
BPF_ARCH_CFLAGS := -D__TARGET_ARCH_arm64
endif
BPF_CFLAGS  ?= -O2 -g -Wall -target bpf $(BPF_INCLUDE) $(BPF_ARCH_CFLAGS)
BINARY      ?= aiblocker-agent
SHIM        ?= aiblocker-shim
POLICYCTL   ?= policyctl

all: bpf build build-policyctl build-shim

# Compile eBPF objects and stage them for go:embed.
bpf:
	cd bpf && $(CLANG) $(BPF_CFLAGS) -c enroll.bpf.c -o enroll.bpf.o
	cd bpf && $(CLANG) $(BPF_CFLAGS) -mllvm -bpf-stack-size=4096 -c enforcer.bpf.c -o enforcer.bpf.o
	mkdir -p cmd/agent/bpf
	cp bpf/enroll.bpf.o cmd/agent/bpf/
	cp bpf/enforcer.bpf.o cmd/agent/bpf/

build:
	go build -o $(BINARY) ./cmd/agent

build-policyctl:
	go build -o $(POLICYCTL) ./cmd/policyctl

build-shim:
	go build -o $(SHIM) ./cmd/shim

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
	rm -f $(BINARY) $(SHIM) $(POLICYCTL)
	rm -f bpf/enroll.bpf.o bpf/enforcer.bpf.o
	rm -f cmd/agent/bpf/enroll.bpf.o cmd/agent/bpf/enforcer.bpf.o

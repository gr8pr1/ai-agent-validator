.PHONY: all bpf build test vet clean run

CLANG       ?= $(shell which clang 2>/dev/null || echo /usr/bin/clang)
BPF_INCLUDE ?= $(shell if [ -d /usr/include/bpf ]; then echo "-I/usr/include"; elif [ -d /usr/local/include/bpf ]; then echo "-I/usr/local/include"; fi)
BINARY      ?= aiblocker-agent

all: bpf build

# Compile the eBPF object and stage it for go:embed.
bpf:
	cd bpf && $(CLANG) -O2 -g -Wall -target bpf $(BPF_INCLUDE) -c enroll.bpf.c -o enroll.bpf.o
	mkdir -p cmd/agent/bpf
	cp bpf/enroll.bpf.o cmd/agent/bpf/

build:
	go build -o $(BINARY) ./cmd/agent

test:
	go test ./...

vet:
	go vet ./...

# Needs root/CAP_BPF for eBPF load + attach.
run: all
	sudo ./$(BINARY) --config config.yaml

clean:
	rm -f $(BINARY)
	rm -f bpf/enroll.bpf.o
	rm -f cmd/agent/bpf/enroll.bpf.o

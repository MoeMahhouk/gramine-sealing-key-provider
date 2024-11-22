# Makefile for Gramine Sealing Key Provider
ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
SGX ?= 1
DEBUG ?= 0
DEV_MODE ?= 0
SELF_EXE = target/release/gramine-sealing-key-provider

# Set flags based on DEV_MODE
ifeq ($(DEV_MODE),1)
CARGO_FLAGS = --features dev-mode
else
CARGO_FLAGS =
endif

.PHONY: all
all: $(SELF_EXE) gramine-sealing-key-provider.manifest
ifeq ($(SGX),1)
all: gramine-sealing-key-provider.manifest.sgx gramine-sealing-key-provider.sig
endif

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
RUST_LOG = debug
else
GRAMINE_LOG_LEVEL = error
RUST_LOG = error
endif

# Print build mode information
.PHONY: print-mode
print-mode:
	@echo "Build Configuration:"
	@echo "  SGX: $(SGX)"
	@echo "  Debug: $(DEBUG)"
	@echo "  Dev Mode: $(DEV_MODE)"
	@echo "  Cargo Flags: $(CARGO_FLAGS)"

$(SELF_EXE): Cargo.toml print-mode
	RUST_LOG=$(RUST_LOG) cargo build --release $(CARGO_FLAGS)

gramine-sealing-key-provider.manifest: gramine-sealing-key-provider.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dself_exe=$(SELF_EXE) \
		-Drust_log=$(RUST_LOG) \
		$< $@

gramine-sealing-key-provider.manifest.sgx gramine-sealing-key-provider.sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: gramine-sealing-key-provider.manifest $(SELF_EXE)
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

.PHONY: run-provider
run-provider: all
	$(GRAMINE) gramine-sealing-key-provider

.PHONY: clean
clean:
	$(RM) -rf *.token *.sig *.manifest.sgx *.manifest

.PHONY: distclean
distclean: clean
	$(RM) -rf target/ Cargo.lock

# Help target
.PHONY: help
help:
	@echo "Gramine Sealing Key Provider Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make SGX=1 DEBUG=1 DEV_MODE=1 run-provider"
	@echo ""
	@echo "Options:"
	@echo "  SGX=1         Enable SGX mode"
	@echo "  DEBUG=1       Enable debug logging"
	@echo "  DEV_MODE=1    Enable development mode (skips TDX quote verification)"
	@echo ""
	@echo "Targets:"
	@echo "  all           Build everything"
	@echo "  run-provider  Run the provider"
	@echo "  clean         Clean build artifacts"
	@echo "  distclean     Clean everything including cargo artifacts"
	@echo "  help          Show this help message"

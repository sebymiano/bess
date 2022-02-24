# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
CLANG_FORMAT_FILE := $(abspath ./.clang-format)

INCLUDES := 
UPF_CFLAGS := -g -Wall
UPF_ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

MODULES_DIR := modules
PROTOBUF_DIR := protobuf

bpf_objects = upf_bpf_main_access.bpf.o upf_bpf_main_core.bpf.o

all: clean $(bpf_objects) gen-go-bindings
	$(call msg,ALL,BPF Objects compiled)

$(bpf_objects): %.bpf.o: ${MODULES_DIR}/%.skel.h

$(MODULES_DIR)/%.skel.h: $(MODULES_DIR)/%.bpf.o
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build BPF code
$(MODULES_DIR)/%.bpf.o: $(MODULES_DIR)/ebpf/%.bpf.c $(wildcard $(MODULES_DIR)/ebpf/%.h)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(UPF_ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

gen-go-bindings:
	$(call msg,GEN-GO-GRPC,$@)
	rm -rf $(PROTOBUF_DIR)/bess_pb
	mkdir -p $(PROTOBUF_DIR)/bess_pb
	protoc $(PROTOBUF_DIR)/*.proto --go_opt=paths=source_relative --go_out=plugins=grpc:$(PROTOBUF_DIR)/bess_pb

format-ebpf:
	clang-format -style=file -i $(MODULES_DIR)/ebpf/*.c $(MODULES_DIR)/ebpf/*.h

format-cpp:
	clang-format -style=file -i $(MODULES_DIR)/*.cc $(MODULES_DIR)/*.h

format: format-ebpf format-cpp

clean:
	rm -f $(MODULES_DIR)/*.skel.h
	rm -rf $(PROTOBUF_DIR)/bess_pb
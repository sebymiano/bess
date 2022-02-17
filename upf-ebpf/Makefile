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

UPF_BPF_HAS_PKG_CONFIG := $(shell command -v $(PKG_CONFIG) 2>&1 >/dev/null && echo yes || echo no)

UPF_BPF_CONFIG_DEPS := libbpf libxdp

ifeq ($(UPF_BPF_HAS_PKG_CONFIG), yes)
  UPF_BPF_PKG_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(UPF_BPF_CONFIG_DEPS))
else
  UPF_BPF_PKG_CFLAGS :=
endif

CXXFLAGS += $(UPF_BPF_PKG_CFLAGS) \
			$(INCLUDES)

$(info [UPF-EBPF] CXXFLAGS is $(CXXFLAGS))

ifdef BESS_LINK_DYNAMIC
  ifeq ($(UPF_BPF_HAS_PKG_CONFIG), yes)
    UPF_PKG_LIBS := $(shell $(PKG_CONFIG) --libs $(UPF_BPF_CONFIG_DEPS))
  else
    UPF_PKG_LIBS := 
  endif
else # Used static libraries
  ifeq ($(UPF_BPF_HAS_PKG_CONFIG), yes)
    UPF_PKG_LIBS := $(shell $(PKG_CONFIG) --static --libs $(UPF_BPF_CONFIG_DEPS))
  endif
endif

LDFLAGS += $(UPF_PKG_LIBS)

$(info [UPF-EBPF] LDFLAGS is $(LDFLAGS))

MODULES_DIR := modules

bpf_objects = upf_bpf_main.bpf.o
cc_objects = modules/upf_bpf_main.o

all: $(bpf_objects)

# modules/upf_bpf_main.o: modules/upf_bpf_main.cc $(PROTO_HEADERS) $(bpf_objects)
# 	ls 
# 	#$(CXX) -o $@ -c $< $(CXXFLAGS) $(DEPFLAGS)

$(bpf_objects): %.bpf.o: ${MODULES_DIR}/%.skel.h

$(MODULES_DIR)/%.skel.h: $(MODULES_DIR)/%.bpf.o
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build BPF code
$(MODULES_DIR)/%.bpf.o: $(MODULES_DIR)/%.bpf.c $(wildcard %.h)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(UPF_ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

clean:
	rm $(MODULES_DIR)/*.skel.h
# format:
# 	clang-format -style=file -i *.c *.h
# 	@grep -n "TODO" *.[ch] || true

# delete failed targets
# .DELETE_ON_ERROR:

# # keep intermediate (.skel.h, .bpf.o, etc) targets
# .SECONDARY:

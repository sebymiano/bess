IGNORE:=$(foreach dir,$(PLUGINS),$(shell if test -f ${dir}/Makefile; then make -C ${dir}; fi;))

UPF_CONFIG_DEPS = libbpf libxdp
UPF_PKG_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(UPF_CONFIG_DEPS))
UPF_PKG_LIBS := $(shell $(PKG_CONFIG) --static --libs $(UPF_CONFIG_DEPS))

CXXFLAGS += $(UPF_PKG_CFLAGS)
LIBS += $(UPF_PKG_LIBS)
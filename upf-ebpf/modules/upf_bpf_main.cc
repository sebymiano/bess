/*
 * Copyright 2021 Sebastiano Miano <mianosebastiano@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

#include <xdp/prog_dispatcher.h>
#include <xdp/libxdp.h>

#include "upf_bpf_main.h"


using bess::utils::be32_t;

const Commands UPFeBPF::cmds = {
    {"add", "UPFeBPFArg",
     MODULE_CMD_FUNC(&UPFeBPF::CommandAdd), Command::THREAD_UNSAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&UPFeBPF::CommandClear),
     Command::THREAD_UNSAFE},
};


CommandResponse
UPFeBPF::Init(const sample::upfebpf::pb::UPFeBPFArg &arg) {
  int err;
  
  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);
  
  /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
  bump_memlock_rlimit();

  /* Open BPF application */
  skel = upf_bpf_main_bpf__open();
  if (!skel) {
      fprintf(stderr, "Failed to open BPF skeleton\n");
      return CommandFailure(1);
  }
  
  prog = xdp_program__from_bpf_obj(skel->obj, "upf_main");

  err = xdp_program__attach(prog, 5, XDP_MODE_NATIVE, 0);

  if (err) {
    fprintf(stderr, "Failed to attach XDP program\n");
    return CommandFailure(1);
  }

  return CommandAdd(arg);
}

CommandResponse UPFeBPF::CommandAdd(
    const sample::upfebpf::pb::UPFeBPFArg &arg) {
  size_t curr = num_vars_;
  if (curr + arg.fields_size() > kMaxVariable) {
    return CommandFailure(EINVAL, "max %zu variables can be specified",
                          kMaxVariable);
  }

  for (int i = 0; i < arg.fields_size(); i++) {
    const auto &var = arg.fields(i);

    size_t size;
    size_t offset;
    be32_t mask;
    uint32_t min;
    uint32_t max;

    offset = var.offset();
    size = var.size();
    min = var.min();
    max = var.max();

    switch (size) {
    case 1:
      mask = be32_t(0x00ffffff);
      min = std::min(min, static_cast<uint32_t>(0xff));
      max = std::min(max, static_cast<uint32_t>(0xff));
      break;

    case 2:
      mask = be32_t(0x0000ffff);
      min = std::min(min, static_cast<uint32_t>(0xffff));
      max = std::min(max, static_cast<uint32_t>(0xffff));
      break;

    case 4:
      mask = be32_t(0x00000000);
      min = std::min(min, static_cast<uint32_t>(0xffffffffu));
      max = std::min(max, static_cast<uint32_t>(0xffffffffu));
      break;

    default:
      return CommandFailure(EINVAL, "'size' must be 1, 2, or 4");
    }

    if (offset + size > SNBUF_DATA) {
      return CommandFailure(EINVAL, "too large 'offset'");
    }

    if (min > max) {
      return CommandFailure(EINVAL, "'min' should not be greater than 'max'");
    }

    vars_[curr + i].offset = offset;
    vars_[curr + i].mask = mask;
    vars_[curr + i].min = min;

    // avoid modulo 0
    vars_[curr + i].range = (max - min + 1) ?: 0xffffffff;
    vars_[curr + i].cur = 0;
    vars_[curr + i].bit_shift = (4 - size) * 8;
  }

  num_vars_ = curr + arg.fields_size();
  return CommandSuccess();
}

CommandResponse UPFeBPF::CommandClear(const bess::pb::EmptyArg &) {
  if (prog != nullptr) {
    xdp_program__detach(prog, 5, XDP_MODE_NATIVE, 0);
    xdp_program__close(prog);
  }
  
  return CommandSuccess();
}

void UPFeBPF::ProcessBatch(__attribute__((unused)) Context *ctx, __attribute__((unused)) bess::PacketBatch *batch) {
  
}

ADD_MODULE(UPFeBPF, "upf-ebpf", "5G UPF built with eBPF/XDP")
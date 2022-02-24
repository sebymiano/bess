/*
 * Copyright 2022 Sebastiano Miano <mianosebastiano@gmail.com>
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

#pragma once

#include "module.h"
#include "utils/endian.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "pb/upf_ebpf_msg.pb.h"

#include "upf_bpf_main_access.skel.h"
#include "upf_bpf_main_core.skel.h"

#include "port_conf.h"

static const size_t kMaxVariable = 16;

static int libbpf_print_fn([[maybe_unused]] enum libbpf_print_level level,
                           const char *format, va_list args) {
  return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void) {
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    exit(1);
  }
}

class UPFeBPF final : public Module {
public:
  static const Commands cmds;

  UPFeBPF()
      : Module(), skel_access_(nullptr), prog_access_(nullptr),
        skel_core_(nullptr), prog_core_(nullptr) {}

  CommandResponse Init(const upf_ebpf::pb::UPFeBPFArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse
  CommandAddPDR(const upf_ebpf::pb::UPFeBPFCommandAddPDRArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);

private:
  int initPorts(const upf_ebpf::pb::UPFeBPFArg &arg);
  int openAndLoadAccess(const upf_ebpf::pb::UPFeBPFArg_Conf &conf);
  int openAndLoadCore(const upf_ebpf::pb::UPFeBPFArg_Conf &conf);

  uint8_t
  pbLogLevelToEbpf(const upf_ebpf::pb::UPFeBPFArg_Conf_LogLevel &log_level);

private:
  size_t num_vars_;
  struct upf_bpf_main_access_bpf *skel_access_;
  struct xdp_program *prog_access_;

  struct upf_bpf_main_core_bpf *skel_core_;
  struct xdp_program *prog_core_;

  int pdr_map_fd_;

  PortConf access_port_;
  PortConf core_port_;
};

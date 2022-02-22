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

#ifndef BESS_MODULES_UPF_BPF_H_
#define BESS_MODULES_UPF_BPF_H_

#include "module.h"
#include "utils/endian.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "pb/upf_ebpf_msg.pb.h"
#include "upf_bpf_main.skel.h"

static const size_t kMaxVariable = 16;

static int libbpf_print_fn([[maybe_unused]] enum libbpf_print_level level, const char *format,
                           va_list args) {
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

  UPFeBPF() : Module(), num_vars_(), vars_() {
    skel = nullptr;
    prog = nullptr;
  }

  CommandResponse Init(const sample::upfebpf::pb::UPFeBPFArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandAdd(const sample::upfebpf::pb::UPFeBPFArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);

private:
  size_t num_vars_;
  struct upf_bpf_main_bpf *skel;
  struct xdp_program *prog;
  struct {
    bess::utils::be32_t mask; // bits with 1 won't be updated
    uint32_t min;
    uint32_t range; // max - min + 1
    uint32_t cur;
    size_t offset;
    size_t bit_shift;
  } vars_[kMaxVariable];
};

#endif // BESS_MODULES_UPF_BPF_H_

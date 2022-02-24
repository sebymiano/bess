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
#include <net/if.h>

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
#include "upf_bpf_structs.h"

using bess::utils::be32_t;

const Commands UPFeBPF::cmds = {
    {"add-pdr", "UPFeBPFCommandAddPDRArg",
     MODULE_CMD_FUNC(&UPFeBPF::CommandAddPDR), Command::THREAD_UNSAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&UPFeBPF::CommandClear),
     Command::THREAD_UNSAFE},
};

int UPFeBPF::initPorts(const upf_ebpf::pb::UPFeBPFArg &arg) {
  int ifindex;

  ifindex = if_nametoindex(arg.conf().access_port().c_str());
  if (!ifindex) {
    return -1;
  }

  access_port_.setIfIndex(ifindex);
  access_port_.setIfName(arg.conf().access_port());

  ifindex = if_nametoindex(arg.conf().core_port().c_str());
  if (!ifindex) {
    return -1;
  }

  core_port_.setIfIndex(ifindex);
  core_port_.setIfName(arg.conf().core_port());

  return 0;
}

int UPFeBPF::openAndLoadAccess(const upf_ebpf::pb::UPFeBPFArg_Conf &conf) {
  int err = 0;

  /* Open BPF application */
  skel_access_ = upf_bpf_main_access_bpf__open();
  if (!skel_access_) {
    fprintf(stderr, "Failed to open BPF access skeleton");
    return -1;
  }

  skel_access_->rodata->upf_cfg.log_level = pbLogLevelToEbpf(conf.log_level());

  prog_access_ =
      xdp_program__from_bpf_obj(skel_access_->obj, "upf_main_access");

  // Attach program to access port
  err = xdp_program__attach(prog_access_, access_port_.getIfIndex(),
                            XDP_MODE_NATIVE, 0);

  if (err) {
    fprintf(stderr, "Failed to attach XDP program to access port");
    return -1;
  }

  return 0;
}

int UPFeBPF::openAndLoadCore(const upf_ebpf::pb::UPFeBPFArg_Conf &conf) {
  int err = 0;

  /* Open BPF application */
  skel_core_ = upf_bpf_main_core_bpf__open();
  if (!skel_core_) {
    fprintf(stderr, "Failed to open BPF core skeleton");
    return -1;
  }

  skel_core_->rodata->upf_cfg.log_level = pbLogLevelToEbpf(conf.log_level());

  prog_core_ = xdp_program__from_bpf_obj(skel_core_->obj, "upf_main_core");

  // Attach program to access port
  err = xdp_program__attach(prog_core_, core_port_.getIfIndex(),
                            XDP_MODE_NATIVE, 0);

  if (err) {
    fprintf(stderr, "Failed to attach XDP program to core port");
    return -1;
  }

  return 0;
}

CommandResponse UPFeBPF::Init(const upf_ebpf::pb::UPFeBPFArg &arg) {
  int err;

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
  bump_memlock_rlimit();

  err = initPorts(arg);
  if (err) {
    return CommandFailure(-1, "Error while initializing ports");
  }

  err = openAndLoadAccess(arg.conf());
  if (err) {
    return CommandFailure(-1, "Failed to attach BPF ACCESS program");
  }

  err = openAndLoadCore(arg.conf());
  if (err) {
    return CommandFailure(-1, "Failed to attach BPF CORE program");
  }

  pdr_map_fd_ = bpf_map__fd(skel_access_->maps.pdr_list_m);
  if (pdr_map_fd_ <= 0) {
    return CommandFailure(-1,
                          "Unable to get file descriptor for map pdr_list_m");
  }

  return CommandSuccess();
}

CommandResponse
UPFeBPF::CommandAddPDR(const upf_ebpf::pb::UPFeBPFCommandAddPDRArg &arg) {
  std::cout << arg.keys().DebugString() << std::endl;
  std::cout << arg.masks().DebugString() << std::endl;
  std::cout << arg.values().DebugString() << std::endl;

  upf_ebpf::pdr_key_t key;
  key.tunnel_ip4_dst = arg.keys().tunnelip4dst();
  key.tunnel_teid = arg.keys().tunnelteid();
  key.ue_ip_src_addr = arg.keys().ueipsrcaddr();
  key.inet_ip_dst_addr = arg.keys().inetipdstaddr();
  key.ue_src_port = arg.keys().uesrcport();
  key.inet_src_port = arg.keys().inetsrcport();
  key.proto_id = arg.keys().protoid();

  upf_ebpf::pdr_value_t value;
  value.pdr_id = arg.values().pdrid();
  value.fse_id = arg.values().fseid();
  value.ctr_id = arg.values().ctrid();
  value.qer_id = arg.values().qerid();
  value.far_id = arg.values().farid();

  // Now it is time to insert the entry in the map
  int ret = bpf_map_update_elem(pdr_map_fd_, static_cast<void *>(&key),
                                static_cast<void *>(&value), BPF_ANY);
  if (ret != 0) {
    return CommandFailure(-1, "bpf_map_update_elem inside addPDR failed");
  }

  return CommandSuccess();
}

CommandResponse UPFeBPF::CommandClear(const bess::pb::EmptyArg &) {
  if (prog_access_ != nullptr) {
    xdp_program__detach(prog_access_, access_port_.getIfIndex(),
                        XDP_MODE_NATIVE, 0);
    xdp_program__close(prog_access_);
  }

  if (prog_core_ != nullptr) {
    xdp_program__detach(prog_core_, core_port_.getIfIndex(), XDP_MODE_NATIVE,
                        0);
    xdp_program__close(prog_core_);
  }

  return CommandSuccess();
}

uint8_t UPFeBPF::pbLogLevelToEbpf(
    const upf_ebpf::pb::UPFeBPFArg_Conf_LogLevel &log_level) {
  switch (log_level) {
  case upf_ebpf::pb::UPFeBPFArg_Conf_LogLevel_ERR:
    return 1;
  case upf_ebpf::pb::UPFeBPFArg_Conf_LogLevel_WARNING:
    return 2;
  case upf_ebpf::pb::UPFeBPFArg_Conf_LogLevel_NOTICE:
    return 3;
  case upf_ebpf::pb::UPFeBPFArg_Conf_LogLevel_INFO:
    return 4;
  case upf_ebpf::pb::UPFeBPFArg_Conf_LogLevel_DEBUG:
    return 5;
  default:
    return 0;
  }
  return 0;
}

void UPFeBPF::ProcessBatch(__attribute__((unused)) Context *ctx,
                           __attribute__((unused)) bess::PacketBatch *batch) {}

ADD_MODULE(UPFeBPF, "upf-ebpf", "5G UPF built with eBPF/XDP")
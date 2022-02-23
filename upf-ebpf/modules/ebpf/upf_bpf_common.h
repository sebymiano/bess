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

#ifndef UPF_BPF_COMMON_H_
#define UPF_BPF_COMMON_H_

#include <linux/if_vlan.h>

const volatile struct { bool enable_printk; } upf_cfg = {};

struct _vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

#define bpf_log_printk(...)                                                    \
    (!upf_cfg.enable_printk ? (0) : bpf_printk(__VA_ARGS__))

#endif // UPF_BPF_COMMON_H_
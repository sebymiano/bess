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

#ifndef UPF_BPF_STRUCTS_H_
#define UPF_BPF_STRUCTS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct pdr_key_s {
  __u32 tunnel_ip4_dst;
  __u32 tunnel_teid;
  __u32 ue_ip_src_addr;
  __u32 inet_ip_dst_addr;
  __u16 ue_src_port;
  __u16 inet_src_port;
  __u8 proto_id;
} __attribute__((__packed__));

typedef struct pdr_key_s pdr_key_t;

struct pdr_value_s {
  __u64 pdr_id;
  __u32 fse_id;
  __u32 ctr_id;
  __u32 qer_id;
  __u32 far_id;
} __attribute__((__packed__));

typedef struct pdr_value_s pdr_value_t;

#endif // UPF_BPF_STRUCTS_H_
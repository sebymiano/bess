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

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace upf_ebpf {

struct pdr_key_s {
  uint32_t tunnel_ip4_dst;
  uint32_t tunnel_teid;
  uint32_t ue_ip_src_addr;
  uint32_t inet_ip_dst_addr;
  uint16_t ue_src_port;
  uint16_t inet_src_port;
  uint8_t proto_id;
} __attribute__((__packed__));

typedef struct pdr_key_s pdr_key_t;

struct pdr_value_s {
  uint64_t pdr_id;
  uint32_t fse_id;
  uint32_t ctr_id;
  uint32_t qer_id;
  uint32_t far_id;
} __attribute__((__packed__));

typedef struct pdr_value_s pdr_value_t;

} // namespace upf_ebpf
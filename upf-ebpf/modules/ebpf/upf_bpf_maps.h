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

#ifndef UPF_BPF_MAPS_H_
#define UPF_BPF_MAPS_H_

#include "upf_bpf_structs.h"
#include <bpf/bpf_helpers.h>

#define PDR_LIST_MAX_SIZE 10000

struct bpf_map_def SEC("maps") pdr_list_m = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(pdr_rule_t),
    .value_size = sizeof(pdr_value_t),
    .max_entries = PDR_LIST_MAX_SIZE,
};

#endif // UPF_BPF_MAPS_H_
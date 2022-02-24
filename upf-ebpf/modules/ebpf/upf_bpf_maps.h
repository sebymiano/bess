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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, sizeof(pdr_key_t));
	__type(value, sizeof(pdr_value_t));
	__uint(max_entries, PDR_LIST_MAX_SIZE);
} pdr_list_m SEC(".maps");

#endif // UPF_BPF_MAPS_H_
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

#ifndef UPF_BPF_PARSE_UTILS_H_
#define UPF_BPF_PARSE_UTILS_H_

#include <linux/if_vlan.h>
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/if_vlan.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

#include "upf_bpf_common.h"

static inline bool validate_ethertype(struct xdp_md *xdp, __u16 *h_proto,
                                      __u16 *nh_off) {
  void *data = (void *)(long)xdp->data;
  void *data_end = (void *)(long)xdp->data_end;

  *nh_off = ETH_HLEN;

  if (data + *nh_off > data_end)
    return false;

  struct ethhdr *eth = (struct ethhdr *)data;
  *h_proto = eth->h_proto;

  if (bpf_ntohs(*h_proto) < ETH_P_802_3_MIN)
    return false; // non-Ethernet II unsupported

// parse double vlans
#pragma unroll
  for (int i = 0; i < 2; i++) {
    if (*h_proto == bpf_ntohs(ETH_P_8021Q) ||
        *h_proto == bpf_ntohs(ETH_P_8021AD)) {
      struct _vlan_hdr *vhdr;
      vhdr = (struct _vlan_hdr *)(data + *nh_off);
      *nh_off += sizeof(struct _vlan_hdr);
      if (data + *nh_off > data_end) {
        return false;
      }
      *h_proto = vhdr->h_vlan_encapsulated_proto;
    }
  }

  return true;
}

#endif // UPF_BPF_PARSE_UTILS_H_
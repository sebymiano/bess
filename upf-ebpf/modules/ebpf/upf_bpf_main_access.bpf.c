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
#include <bpf/bpf_endian.h>

#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

#include "upf_bpf_common.h"
#include "bpf_log.h"
#include "parse_utils.h"
#include "gtp_utils.h"
#include "upf_bpf_maps.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("upf_main_access")
int xdp_upf(struct xdp_md *xdp) {
  void *data_end = (void *)(long)xdp->data_end;
  void *data = (void *)(long)xdp->data;

  __u16 l3_proto;
  __u16 nh_off;
  bpf_log_debug("[Access] Received packet on interface ACCESS\n");

  if (!validate_ethertype(xdp, &l3_proto, &nh_off)) {
    bpf_log_err("[Access] Unrecognized L3 protocol\n");
    goto DROP;
  }

  switch (l3_proto) {
  case bpf_htons(ETH_P_IP):
    goto IP; // ipv4 packet
  case bpf_htons(ETH_P_IPV6):
    // TODO: Maybe in the future we want to support IPv6 as well
    goto IP6;
    break;
  case bpf_htons(ETH_P_ARP):
    goto ARP; // arp packet
  default:
    goto DROP;
  }

IP:;
  struct iphdr *iph = data + nh_off;
  if ((void *)iph + sizeof(*iph) > data_end) {
    bpf_log_err("[Access] Invalid IPv4 packet\n");
    goto DROP;
  }

  // Probably we need to perform additional checks here.
  // E.g., we might want to check if the packet has dst address equal to the
  // N3 interface of the UPF

  if (iph->protocol != IPPROTO_UDP) {
    bpf_log_err("[Access] Received non-UDP packet\n");
    return XDP_PASS;
  }

UDP:;
  struct udphdr *udp = (void *)iph + 4 * iph->ihl;
  if ((void *)udp + sizeof(*udp) > data_end) {
    bpf_log_err("[Access] Invalid UDP packet\n");
    goto DROP;
  }

  __u32 teid;

  if (udp->dest == bpf_htons(GTP_PORT)) {
    if (!parse_and_validate_gtp(xdp, udp, &teid)) {
      bpf_log_err("[Access] Invalid GTP packet\n");
      goto DROP;
    } else {
      goto PDR_LOOKUP;
    }
  } else {
    bpf_log_debug("[Access] UDP packet received but not matching GTP port\n");
  }

PDR_LOOKUP:;
  bpf_log_info("[Access] GTP packet parsed and extracted TEID = %u\n", teid);
  return XDP_PASS;

IP6:;
  bpf_log_debug("[Access] Received IPv6 Packet. Dropping\n");
  return XDP_DROP;

ARP:;
  // TODO: To be implemented. We can handle the ARP in the data plane,
  // or we can send the packet to userspace and let BESS handle it.
  bpf_log_debug("[Access] Received ARP.\n");
  return XDP_DROP;

DROP:;
  bpf_log_debug("[Access] Dropping packet.\n");
  return XDP_DROP;
}
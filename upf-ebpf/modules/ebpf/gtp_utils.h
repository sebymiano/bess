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

#ifndef UPF_BPF_GTP_UTILS_H_
#define UPF_BPF_GTP_UTILS_H_

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
#include "bpf_log.h"

#define GTP_PORT 2152
#define GTP_TYPE_GPDU 255 // User data packet (T-PDU) plus GTP-U header
#define GTP_FLAGS 0x30    // Version: GTPv1, Protocol Type: GTP, Others: 0

struct gtpv1_header { /* According to 3GPP TS 29.060. */
  __u8 flags;
  __u8 type;
  __be16 length;
  __be32 tid;
} __attribute__((packed));

static inline bool parse_and_validate_gtp(struct xdp_md *xdp,
                                          struct udphdr *udp, __u32 *teid) {
  void *data = (void *)(long)xdp->data;
  void *data_end = (void *)(long)xdp->data_end;

  struct gtpv1_header *gtp =
      (struct gtpv1_header *)((void *)udp + sizeof(*udp));
  if ((void *)gtp + sizeof(*gtp) > data_end) {
    return false;
  }

  if (gtp->type != GTP_TYPE_GPDU) {
    bpf_log_debug("Message type is not GTPU\n");
    return false;
  }

  *teid = gtp->tid;
  return true;
}

#endif // UPF_BPF_GTP_UTILS_H_
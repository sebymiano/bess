// Copyright (c) 2014-2016, The Regents of the University of California.
// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include "pmd.h"

#include <rte_bus_pci.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_pmd_i40e.h>

#include "../utils/ether.h"
#include "../utils/format.h"

// TODO: Replace with one time initialized key during InitDriver?
static uint8_t rss_key[40] = {0xD8, 0x2A, 0x6C, 0x5A, 0xDD, 0x3B, 0x9D, 0x1E,
                              0x14, 0xCE, 0x2F, 0x37, 0x86, 0xB2, 0x69, 0xF0,
                              0x44, 0x31, 0x7E, 0xA2, 0x07, 0xA5, 0x0A, 0x99,
                              0x49, 0xC6, 0xA4, 0xFE, 0x0C, 0x4F, 0x59, 0x02,
                              0xD4, 0x44, 0xE2, 0x4A, 0xDB, 0xE1, 0x05, 0x82};

static const rte_eth_conf default_eth_conf(const rte_eth_dev_info &dev_info,
                                           int nb_rxq) {
  rte_eth_conf ret = {};

  ret.link_speeds = ETH_LINK_SPEED_AUTONEG;
  ret.rxmode.mq_mode = (nb_rxq > 1) ? ETH_MQ_RX_RSS : ETH_MQ_RX_NONE;
  ret.rxmode.offloads = 0;

  ret.rx_adv_conf.rss_conf = {
      .rss_key = rss_key,
      .rss_key_len = sizeof(rss_key),
      .rss_hf = (ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP | ETH_RSS_SCTP) &
                dev_info.flow_type_rss_offloads,
  };

  return ret;
}

void PMDPort::InitDriver() {
  dpdk_port_t num_dpdk_ports = rte_eth_dev_count_avail();

  LOG(INFO) << static_cast<int>(num_dpdk_ports)
            << " DPDK PMD ports have been recognized:";

  for (dpdk_port_t i = 0; i < num_dpdk_ports; i++) {
    rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(i, &dev_info);

    bess::utils::Ethernet::Address lladdr;
    rte_eth_macaddr_get(i, reinterpret_cast<rte_ether_addr *>(lladdr.bytes));

    int numa_node = rte_eth_dev_socket_id(static_cast<int>(i));

    std::string pci_info;
    if (dev_info.device) {
      rte_bus *bus = rte_bus_find_by_device(dev_info.device);
      if (bus && !strcmp(bus->name, "pci")) {
        rte_pci_device *pci_dev = RTE_DEV_TO_PCI(dev_info.device);
        pci_info = bess::utils::Format(
            "%08x:%02hhx:%02hhx.%02hhx %04hx:%04hx  ", pci_dev->addr.domain,
            pci_dev->addr.bus, pci_dev->addr.devid, pci_dev->addr.function,
            pci_dev->id.vendor_id, pci_dev->id.device_id);
      }
    }

    LOG(INFO) << "DPDK port_id " << static_cast<int>(i) << " ("
              << dev_info.driver_name << ")   RXQ " << dev_info.max_rx_queues
              << " TXQ " << dev_info.max_tx_queues << "  " << lladdr.ToString()
              << "  " << pci_info << " numa_node " << numa_node;
  }
}

// Find a port attached to DPDK by its integral id.
// returns 0 and sets *ret_port_id to "port_id" if the port is valid and
// available.
// returns > 0 on error.
static CommandResponse find_dpdk_port_by_id(dpdk_port_t port_id,
                                            dpdk_port_t *ret_port_id) {
  if (port_id >= RTE_MAX_ETHPORTS) {
    return CommandFailure(EINVAL, "Invalid port id %d", port_id);
  }
  if (rte_eth_devices[port_id].state != RTE_ETH_DEV_ATTACHED) {
    return CommandFailure(ENODEV, "Port id %d is not available", port_id);
  }

  *ret_port_id = port_id;
  return CommandSuccess();
}

// Find a port attached to DPDK by its PCI address.
// returns 0 and sets *ret_port_id to the port_id of the port at PCI address
// "pci" if it is valid and available. *ret_hot_plugged is set to true if the
// device was attached to DPDK as a result of calling this function.
// returns > 0 on error.
static CommandResponse find_dpdk_port_by_pci_addr(const std::string &pci,
                                                  dpdk_port_t *ret_port_id,
                                                  bool *ret_hot_plugged) {
  dpdk_port_t port_id = DPDK_PORT_UNKNOWN;

  if (pci.length() == 0) {
    return CommandFailure(EINVAL, "No PCI address specified");
  }

  rte_pci_addr addr;
  if (rte_pci_addr_parse(pci.c_str(), &addr) != 0) {
    return CommandFailure(EINVAL,
                          "PCI address must be like "
                          "dddd:bb:dd.ff or bb:dd.ff");
  }

  const rte_bus *bus = nullptr;

  dpdk_port_t num_dpdk_ports = rte_eth_dev_count_avail();
  for (dpdk_port_t i = 0; i < num_dpdk_ports; i++) {
    rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(i, &dev_info);

    if (dev_info.device) {
      bus = rte_bus_find_by_device(dev_info.device);
      if (bus && !strcmp(bus->name, "pci")) {
        const rte_pci_device *pci_dev = RTE_DEV_TO_PCI(dev_info.device);
        if (rte_pci_addr_cmp(&addr, &pci_dev->addr) == 0) {
          port_id = i;
          break;
        }
      }
    }
  }

  // If still not found, maybe the device has not been attached yet
  if (port_id == DPDK_PORT_UNKNOWN) {
    int ret;
    char name[RTE_ETH_NAME_MAX_LEN];
    snprintf(name, RTE_ETH_NAME_MAX_LEN, "%08x:%02x:%02x.%02x", addr.domain,
             addr.bus, addr.devid, addr.function);

    ret = rte_eal_hotplug_add("pci", name, "");
    if (ret < 0) {
      return CommandFailure(ENODEV, "Cannot attach PCI device %s", name);
    }
    ret = rte_eth_dev_get_port_by_name(name, &port_id);
    if (ret < 0) {
      return CommandFailure(ENODEV, "Cannot find port id for PCI device %s",
                            name);
    }
    *ret_hot_plugged = true;
  }

  *ret_port_id = port_id;
  return CommandSuccess();
}

// Find a DPDK vdev by name.
// returns 0 and sets *ret_port_id to the port_id of "vdev" if it is valid and
// available. *ret_hot_plugged is set to true if the device was attached to
// DPDK as a result of calling this function.
// returns > 0 on error.
static CommandResponse find_dpdk_vdev(const std::string &vdev,
                                      dpdk_port_t *ret_port_id,
                                      bool *ret_hot_plugged) {
  dpdk_port_t port_id = DPDK_PORT_UNKNOWN;

  if (vdev.length() == 0) {
    return CommandFailure(EINVAL, "No vdev specified");
  }

  int ret = rte_dev_probe(vdev.c_str());
  if (ret < 0) {
    return CommandFailure(ENODEV, "Cannot attach vdev %s", vdev.c_str());
  }

  rte_dev_iterator iterator;
  RTE_ETH_FOREACH_MATCHING_DEV(port_id, vdev.c_str(), &iterator) {
    LOG(INFO) << "port id: " << port_id << "matches vdev: " << vdev;
    rte_eth_iterator_cleanup(&iterator);
    break;
  }

  *ret_hot_plugged = true;
  *ret_port_id = port_id;
  return CommandSuccess();
}

/* Create RSS on inner source IP. */
CommandResponse create_gtp_u_inner_ip_rss_flow(dpdk_port_t port_id,
                                              const uint32_t &flow_profile, 
                                              uint64_t rss_types,
                                              const int &num_rxq, bool config_queues = true) {
  uint16_t queues[num_rxq];
  int i, nb_queues;
  for (i = 0, nb_queues = 0; i < num_rxq; i++) {
    queues[nb_queues++] = i;
  }

	struct rte_flow *flow;
	struct rte_flow_error err;
	
  struct rte_flow_attr attr; /* Holds the flow attributes. */
  memset(&attr, 0, sizeof(attr));
  attr.group = 0; /* set the rule on the main group. */
  attr.ingress = 1;/* Rx flow. */
  attr.priority = 1; /* add priority to rule
  to give the Decap rule higher priority since
  it is more specific */
	
  struct rte_flow_item_gtp gtp_spec;
  memset(&gtp_spec, 0, sizeof(gtp_spec));
	gtp_spec.msg_type = 255; /* The expected value. */
	
  struct rte_flow_item_gtp gtp_mask;
  memset(&gtp_mask, 0, sizeof(gtp_mask));
	gtp_mask.msg_type = 0xff; /* match only message type.
	mask bit equal to 1 means match on this bit. */
	
  struct rte_flow_action_rss rss;
  memset(&rss, 0, sizeof(rss));
  rss.level = 2; /* RSS should be done on inner header. */
  if (config_queues) {
    rss.queue = queues; /* Set the selected target queues. */
    rss.queue_num = nb_queues; /* The number of queues. */
  }
  rss.types =  rss_types; //ETH_RSS_IP | ETH_RSS_L3_SRC_ONLY

  struct rte_flow_action actions[2];
  memset(actions, 0, sizeof(actions));

  /* The RSS action to be used. */
	actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
  actions[0].conf = &rss;
  /* End action mast be the last action. */
  actions[1].type = RTE_FLOW_ACTION_TYPE_END;
  actions[1].conf = NULL;

	/* Configure matching on outer ipv4 and GTP-U.
	 * This case we don't care about specific outer ipv4 or UDP we just 
	 * seach for any header that maches eth / ipv4 / udp / gtp type 255 / 
	 * ipv4 / udp.
	 * The RSS will only be done on the inner ipv4 src file, in order to 
	 * make sure that all of the packets from a given user (inner source
	 * ip) will be routed to the same core.
	 */
  struct rte_flow_item pattern[5];
  memset(pattern, 0, sizeof(pattern));

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[3].type = RTE_FLOW_ITEM_TYPE_GTP;
	pattern[3].spec = &gtp_spec;
	pattern[3].mask = &gtp_mask;
  pattern[4].type = RTE_FLOW_ITEM_TYPE_END;
  char buf[32];
	
	int ret = rte_flow_validate(port_id, &attr, pattern, actions, &err);
  if (ret)
    return CommandFailure(EINVAL,
                          "Port %u: Failed to validate flow profile %u %s",
                          port_id, flow_profile, err.message);
  flow = rte_flow_create(port_id, &attr, pattern, actions, &err);
  if (flow == nullptr)
    return CommandFailure(EINVAL, "Port %u: Failed to create flow: Type %d (%s), message: %s (%s) (profile %u)", port_id,
                          err.type, 
                          err.cause ? (snprintf(buf, sizeof(buf), "cause: %p, ", err.cause), buf) : "",
                          err.message, 
                          rte_strerror(rte_errno), 
                          flow_profile);

  return CommandSuccess();

}

/* Get dynamic device personalization profile info list*/
#define PROFILE_INFO_SIZE 48
#define MAX_PROFILE_NUM 16

static void ddp_get_list(dpdk_port_t port_id) {
	struct rte_pmd_i40e_profile_list *p_list;
	struct rte_pmd_i40e_profile_info *p_info;
	uint32_t p_num;
	uint32_t size;
	uint32_t i;
	int ret = -ENOTSUP;

	size = PROFILE_INFO_SIZE * MAX_PROFILE_NUM + 4;
	p_list = (struct rte_pmd_i40e_profile_list *)malloc(size);
	if (!p_list) {
		fprintf(stderr, "%s: Failed to malloc buffer\n", __func__);
		return;
	}

	if (ret == -ENOTSUP)
		ret = rte_pmd_i40e_get_ddp_list(port_id,
						(uint8_t *)p_list, size);

	if (!ret) {
		p_num = p_list->p_count;
		printf("Profile number is: %d\n\n", p_num);

		for (i = 0; i < p_num; i++) {
			p_info = &p_list->p_info[i];
			printf("Profile %d:\n", i);
			printf("Track id:     0x%x\n", p_info->track_id);
			printf("Version:      %d.%d.%d.%d\n",
			       p_info->version.major,
			       p_info->version.minor,
			       p_info->version.update,
			       p_info->version.draft);
			printf("Profile name: %s\n\n", p_info->name);
		}
	}

	free(p_list);

	if (ret < 0)
		fprintf(stderr, "Failed to get ddp list\n");
}

static void cmd_pctype_mapping_update_parsed(dpdk_port_t port_id) {
	int ret = -ENOTSUP;
	struct rte_pmd_i40e_flow_type_mapping mapping;

	mapping.flow_type = 22;
  mapping.pctype = 0ULL;
  mapping.pctype |= (1ULL << 22);
	ret = rte_pmd_i40e_flow_type_mapping_update(port_id, &mapping, 1, 0);

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		fprintf(stderr, "invalid pctype or flow type\n");
		break;
	case -ENODEV:
		fprintf(stderr, "invalid port_id %d\n", port_id);
		break;
	case -ENOTSUP:
		fprintf(stderr, "function not implemented\n");
		break;
	default:
		fprintf(stderr, "programming error: (%s)\n", strerror(-ret));
	}
}

static int eth_dev_info_get_print_err(uint16_t port_id, struct rte_eth_dev_info *dev_info)
{
	int ret;

	ret = rte_eth_dev_info_get(port_id, dev_info);
	if (ret != 0)
		fprintf(stderr,
			"Error during getting device (port %u) info: %s\n",
			port_id, strerror(-ret));

	return ret;
}

static void config_rss(uint16_t port_id) {
	struct rte_eth_rss_conf rss_conf;
  memset(&rss_conf, 0, sizeof(rss_conf));
  rss_conf.rss_key_len = 0;

	struct rte_eth_dev_info dev_info;
  memset(&dev_info, 0, sizeof(dev_info));
  dev_info.flow_type_rss_offloads = 0;

	int use_default = 0;
	int all_updated = 1;
	int diag;
	int ret;

  rss_conf.rss_hf = 1ULL << 22;
	rss_conf.rss_key = NULL;
	/* Update global configuration for RSS types. */
  struct rte_eth_rss_conf local_rss_conf;

  ret = eth_dev_info_get_print_err(port_id, &dev_info);
  if (ret != 0)
    return;

  if (use_default)
    rss_conf.rss_hf = dev_info.flow_type_rss_offloads;

  local_rss_conf = rss_conf;
  local_rss_conf.rss_hf = rss_conf.rss_hf & dev_info.flow_type_rss_offloads;
  if (local_rss_conf.rss_hf != rss_conf.rss_hf) {
    printf("Port %u modified RSS hash function based on hardware support,"
      "requested:%#" PRIx64 " configured:%#" PRIx64 "\n",
      port_id, rss_conf.rss_hf, local_rss_conf.rss_hf);
  }
  diag = rte_eth_dev_rss_hash_update(port_id, &local_rss_conf);
  if (diag < 0) {
    all_updated = 0;
    fprintf(stderr,
      "Configuration of RSS hash at ethernet port %d failed with error (%d): %s.\n",
      port_id, -diag, strerror(-diag));
  }

	if (all_updated && !use_default) {
		printf("rss_hf %#" PRIx64 "\n", rss_conf.rss_hf);
	}
}

CommandResponse i40e_create_gtp_u_inner_ip_rss_flow(dpdk_port_t port_id) {
  ddp_get_list(port_id);
  cmd_pctype_mapping_update_parsed(port_id);
  config_rss(port_id);

  return CommandSuccess();

}

CommandResponse flow_create_one(dpdk_port_t port_id,
                                const uint32_t &flow_profile, int size,
                                uint64_t rss_types,
                                rte_flow_item_type *pattern) {
  struct rte_flow_item items[size];
  memset(items, 0, sizeof(items));

  for (int i = 0; i < size; i++) {
    items[i].type = pattern[i];
    items[i].spec = nullptr;
    items[i].mask = nullptr;
  }

  struct rte_flow *handle;
  struct rte_flow_error err;
  memset(&err, 0, sizeof(err));

  struct rte_flow_action actions[2];
  memset(actions, 0, sizeof(actions));

  struct rte_flow_attr attributes;
  memset(&attributes, 0, sizeof(attributes));
  attributes.ingress = 1;

  struct rte_flow_action_rss action_rss;
  memset(&action_rss, 0, sizeof(action_rss));
  action_rss.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
  action_rss.key_len = 0;
  action_rss.types = rss_types;

  actions[0].type = RTE_FLOW_ACTION_TYPE_RSS;
  actions[0].conf = &action_rss;
  actions[1].type = RTE_FLOW_ACTION_TYPE_END;

  int ret = rte_flow_validate(port_id, &attributes, items, actions, &err);
  if (ret)
    return CommandFailure(EINVAL,
                          "Port %u: Failed to validate flow profile %u %s",
                          port_id, flow_profile, err.message);

  handle = rte_flow_create(port_id, &attributes, items, actions, &err);
  if (handle == nullptr)
    return CommandFailure(EINVAL, "Port %u: Failed to create flow %s", port_id,
                          err.message);

  return CommandSuccess();
}

#define NUM_ELEMENTS(x) (sizeof(x) / sizeof((x)[0]))

enum FlowProfile : uint32_t
{
  profileN3 = 3,
  profileN6 = 6,
  profileN9 = 9,
};

CommandResponse flow_create(dpdk_port_t port_id, const uint32_t &flow_profile, const int &num_rxq, const std::string &driver_name) {
  CommandResponse err;

  rte_flow_item_type N39_NSA[] = {
      RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4, RTE_FLOW_ITEM_TYPE_UDP,
      RTE_FLOW_ITEM_TYPE_GTPU, RTE_FLOW_ITEM_TYPE_IPV4,
      RTE_FLOW_ITEM_TYPE_END};

  rte_flow_item_type N6[] = {
      RTE_FLOW_ITEM_TYPE_ETH, RTE_FLOW_ITEM_TYPE_IPV4,
      RTE_FLOW_ITEM_TYPE_END};

  switch (flow_profile) {
    uint64_t rss_types;
    // N3 traffic with and without PDU Session container
    case profileN3:
      rss_types = ETH_RSS_IP | ETH_RSS_L3_SRC_ONLY;
      if (driver_name == "mlx5_pci") {
        err = create_gtp_u_inner_ip_rss_flow(port_id, flow_profile, rss_types, num_rxq);
      } else if (driver_name == "net_i40e") {
        err = i40e_create_gtp_u_inner_ip_rss_flow(port_id);
      } else {
        err = flow_create_one(port_id, flow_profile, NUM_ELEMENTS(N39_NSA),
                              rss_types, N39_NSA);
      }
      if (err.error().code() != 0) {
        return err;
      }
      break;

    // N6 traffic
    case profileN6:
      if (driver_name != "net_i40e") {
        rss_types = ETH_RSS_IPV4 | ETH_RSS_L3_DST_ONLY;
        err = flow_create_one(port_id, flow_profile, NUM_ELEMENTS(N6),
                              rss_types, N6);
      }
      break;

    // N9 traffic with and without PDU Session container
    case profileN9:
      //TODO: Handle this case
      break;

    default:
      return CommandFailure(EINVAL, "Unknown flow profile %u", flow_profile);
  }
  return err;
}

CommandResponse PMDPort::Init(const bess::pb::PMDPortArg &arg) {
  dpdk_port_t ret_port_id = DPDK_PORT_UNKNOWN;

  rte_eth_dev_info dev_info;
  rte_eth_conf eth_conf;
  rte_eth_rxconf eth_rxconf;

  int num_txq = num_queues[PACKET_DIR_OUT];
  int num_rxq = num_queues[PACKET_DIR_INC];

  int ret;

  CommandResponse err;
  switch (arg.port_case()) {
    case bess::pb::PMDPortArg::kPortId: {
      err = find_dpdk_port_by_id(arg.port_id(), &ret_port_id);
      break;
    }
    case bess::pb::PMDPortArg::kPci: {
      err = find_dpdk_port_by_pci_addr(arg.pci(), &ret_port_id, &hot_plugged_);
      break;
    }
    case bess::pb::PMDPortArg::kVdev: {
      err = find_dpdk_vdev(arg.vdev(), &ret_port_id, &hot_plugged_);
      break;
    }
    default:
      return CommandFailure(EINVAL, "No port specified");
  }

  if (err.error().code() != 0) {
    return err;
  }

  if (ret_port_id == DPDK_PORT_UNKNOWN) {
    return CommandFailure(ENOENT, "Port not found");
  }

  /* Use defaut rx/tx configuration as provided by PMD drivers,
   * with minor tweaks */
  rte_eth_dev_info_get(ret_port_id, &dev_info);

  eth_conf = default_eth_conf(dev_info, num_rxq);
  if (arg.loopback()) {
    eth_conf.lpbk_mode = 1;
  }
  if (arg.hwcksum()) {
    eth_conf.rxmode.offloads = DEV_RX_OFFLOAD_IPV4_CKSUM |
                               DEV_RX_OFFLOAD_UDP_CKSUM |
                               DEV_RX_OFFLOAD_TCP_CKSUM;
  }

  ret = rte_eth_dev_configure(ret_port_id, num_rxq, num_txq, &eth_conf);
  if (ret != 0) {
    VLOG(1) << "Failed to configure with hardware checksum offload. "
            << "Create PMDPort without hardware offload" << std::endl;
    return CommandFailure(-ret, "rte_eth_dev_configure() failed");
  }

  int sid = arg.socket_case() == bess::pb::PMDPortArg::kSocketId ?
	  arg.socket_id() : rte_eth_dev_socket_id(ret_port_id);
  /* if soocket_id is invalid, set to 0 */
  if (sid < 0 || sid > RTE_MAX_NUMA_NODES) {
    LOG(WARNING) << "Invalid socket, falling back... ";
    sid = 0;
  }
  LOG(INFO) << "Initializing Port:" << ret_port_id
	    << " with memory from socket " << sid;

  eth_rxconf = dev_info.default_rxconf;
  eth_rxconf.rx_drop_en = 1;

  if (dev_info.rx_desc_lim.nb_min > 0 &&
      queue_size[PACKET_DIR_INC] < dev_info.rx_desc_lim.nb_min) {
    int old_size_rxq = queue_size[PACKET_DIR_INC];
    queue_size[PACKET_DIR_INC] = dev_info.rx_desc_lim.nb_min;
    LOG(WARNING) << "resizing RX queue size from " << old_size_rxq << " to "
                 << queue_size[PACKET_DIR_INC];
  }

  if (dev_info.rx_desc_lim.nb_max > 0 &&
      queue_size[PACKET_DIR_INC] > dev_info.rx_desc_lim.nb_max) {
    int old_size_rxq = queue_size[PACKET_DIR_INC];
    queue_size[PACKET_DIR_INC] = dev_info.rx_desc_lim.nb_max;
    LOG(WARNING) << "capping RX queue size from " << old_size_rxq << " to "
                 << queue_size[PACKET_DIR_INC];
  }

  for (int i = 0; i < num_rxq; i++) {
    ret = rte_eth_rx_queue_setup(ret_port_id, i, queue_size[PACKET_DIR_INC],
                                 sid, &eth_rxconf,
                                 bess::PacketPool::GetDefaultPool(sid)->pool());
    if (ret != 0) {
      return CommandFailure(-ret, "rte_eth_rx_queue_setup() failed");
    }
  }

  if (dev_info.tx_desc_lim.nb_min > 0 &&
      queue_size[PACKET_DIR_OUT] < dev_info.tx_desc_lim.nb_min) {
    int old_size_txq = queue_size[PACKET_DIR_OUT];
    queue_size[PACKET_DIR_OUT] = dev_info.tx_desc_lim.nb_min;
    LOG(WARNING) << "resizing TX queue size from " << old_size_txq << " to "
                 << queue_size[PACKET_DIR_OUT];
  }

  if (dev_info.tx_desc_lim.nb_max > 0 &&
      queue_size[PACKET_DIR_OUT] > dev_info.tx_desc_lim.nb_max) {
    int old_size_txq = queue_size[PACKET_DIR_OUT];
    queue_size[PACKET_DIR_OUT] = dev_info.tx_desc_lim.nb_max;
    LOG(WARNING) << "capping TX queue size from " << old_size_txq << " to "
                 << queue_size[PACKET_DIR_OUT];
  }

  for (int i = 0; i < num_txq; i++) {
    ret = rte_eth_tx_queue_setup(ret_port_id, i, queue_size[PACKET_DIR_OUT],
                                 sid, nullptr);
    if (ret != 0) {
      return CommandFailure(-ret, "rte_eth_tx_queue_setup() failed");
    }
  }

  if (arg.promiscuous_mode()) {
    ret = rte_eth_promiscuous_enable(ret_port_id);
    if (ret != 0) {
      return CommandFailure(-ret, "rte_eth_promiscuous_enable() failed");
    }
  }

  int offload_mask = 0;
  offload_mask |= arg.vlan_offload_rx_strip() ? ETH_VLAN_STRIP_OFFLOAD : 0;
  offload_mask |= arg.vlan_offload_rx_filter() ? ETH_VLAN_FILTER_OFFLOAD : 0;
  offload_mask |= arg.vlan_offload_rx_qinq() ? ETH_VLAN_EXTEND_OFFLOAD : 0;
  if (offload_mask) {
    ret = rte_eth_dev_set_vlan_offload(ret_port_id, offload_mask);
    if (ret != 0) {
      return CommandFailure(-ret, "rte_eth_dev_set_vlan_offload() failed");
    }
  }

  ret = rte_eth_dev_start(ret_port_id);
  if (ret != 0) {
    return CommandFailure(-ret, "rte_eth_dev_start() failed");
  }
  dpdk_port_id_ = ret_port_id;

  int numa_node = arg.socket_case() == bess::pb::PMDPortArg::kSocketId ?
              sid : rte_eth_dev_socket_id(ret_port_id);
  node_placement_ =
      numa_node == -1 ? UNCONSTRAINED_SOCKET : (1ull << numa_node);

  rte_eth_macaddr_get(dpdk_port_id_,
                      reinterpret_cast<rte_ether_addr *>(conf_.mac_addr.bytes));

  // Reset hardware stat counters, as they may still contain previous data
  CollectStats(true);

  driver_ = dev_info.driver_name ?: "unknown";

  LOG(INFO) << "Driver name: " << driver_;

  if (arg.flow_profiles_size() > 0) {
    for (int i = 0; i < arg.flow_profiles_size(); ++i) {
      err = flow_create(ret_port_id, arg.flow_profiles(i), num_rxq, driver_);
      if (err.error().code() != 0) {
        return err;
      }
    }
  }

  return CommandSuccess();
}

CommandResponse PMDPort::UpdateConf(const Conf &conf) {
  CommandResponse resp = CommandSuccess();
  rte_eth_dev_stop(dpdk_port_id_);  // need to restart before return

  if (conf_.mtu != conf.mtu && conf.mtu != 0) {
    if (conf.mtu > SNBUF_DATA || conf.mtu < RTE_ETHER_MIN_MTU) {
      resp = CommandFailure(EINVAL, "mtu should be >= %d and <= %d",
                            RTE_ETHER_MIN_MTU, SNBUF_DATA);
      goto restart;
    }

    int ret = rte_eth_dev_set_mtu(dpdk_port_id_, conf.mtu);
    if (ret == 0) {
      conf_.mtu = conf.mtu;
    } else {
      resp = CommandFailure(-ret, "rte_eth_dev_set_mtu() failed");
      goto restart;
    }
  }

  if (conf_.mac_addr != conf.mac_addr && !conf.mac_addr.IsZero()) {
    rte_ether_addr tmp;
    rte_ether_addr_copy(
        reinterpret_cast<const rte_ether_addr *>(&conf.mac_addr.bytes), &tmp);
    int ret = rte_eth_dev_default_mac_addr_set(dpdk_port_id_, &tmp);
    if (ret == 0) {
      conf_.mac_addr = conf.mac_addr;
    } else {
      resp = CommandFailure(-ret, "rte_eth_dev_default_mac_addr_set() failed");
      goto restart;
    }
  }

restart:
  if (conf.admin_up) {
    int ret = rte_eth_dev_start(dpdk_port_id_);
    if (ret == 0) {
      conf_.admin_up = true;
    } else {
      return CommandFailure(-ret, "rte_eth_dev_start() failed");
    }
  }

  return resp;
}

void PMDPort::DeInit() {
  struct rte_flow_error err;
  memset(&err, 0, sizeof(err));
  rte_flow_flush(dpdk_port_id_, &err);

  rte_eth_dev_stop(dpdk_port_id_);

  if (hot_plugged_) {
    rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(dpdk_port_id_, &dev_info);

    char name[RTE_ETH_NAME_MAX_LEN];
    int ret;

    if (dev_info.device) {
      rte_bus *bus = rte_bus_find_by_device(dev_info.device);
      if (rte_eth_dev_get_name_by_port(dpdk_port_id_, name) == 0) {
        rte_eth_dev_close(dpdk_port_id_);
        ret = rte_eal_hotplug_remove(bus->name, name);
        if (ret < 0) {
          LOG(WARNING) << "rte_eal_hotplug_remove("
                       << static_cast<int>(dpdk_port_id_)
                       << ") failed: " << rte_strerror(-ret);
        }
        return;
      } else {
        LOG(WARNING) << "rte_eth_dev_get_name failed for port"
                     << static_cast<int>(dpdk_port_id_);
      }
    } else {
      LOG(WARNING) << "rte_eth_def_info_get failed for port"
                   << static_cast<int>(dpdk_port_id_);
    }

    rte_eth_dev_close(dpdk_port_id_);
  }
}

void PMDPort::CollectStats(bool reset) {
  packet_dir_t dir;
  queue_t qid;

  if (reset) {
    rte_eth_stats_reset(dpdk_port_id_);
    return;
  }

  rte_eth_stats stats;
  int ret = rte_eth_stats_get(dpdk_port_id_, &stats);
  if (ret < 0) {
    LOG(ERROR) << "rte_eth_stats_get(" << static_cast<int>(dpdk_port_id_)
               << ") failed: " << rte_strerror(-ret);
    return;
  }

  VLOG(1) << bess::utils::Format(
      "PMD port %d: ipackets %" PRIu64 " opackets %" PRIu64 " ibytes %" PRIu64
      " obytes %" PRIu64 " imissed %" PRIu64 " ierrors %" PRIu64
      " oerrors %" PRIu64 " rx_nombuf %" PRIu64,
      dpdk_port_id_, stats.ipackets, stats.opackets, stats.ibytes, stats.obytes,
      stats.imissed, stats.ierrors, stats.oerrors, stats.rx_nombuf);

  port_stats_.inc.dropped = stats.imissed;

  // ice/i40e/net_e1000_igb PMD drivers, ixgbevf and net_bonding vdevs don't
  // support per-queue stats
  if (driver_ == "net_ice" || driver_ == "net_iavf" ||
      driver_ == "net_i40e" || driver_ == "net_i40e_vf" ||
      driver_ == "net_ixgbe_vf" || driver_ == "net_bonding" ||
      driver_ == "net_e1000_igb") {
    // NOTE:
    // - if link is down, tx bytes won't increase
    // - if destination MAC address is incorrect, rx pkts won't increase
    port_stats_.inc.packets = stats.ipackets;
    port_stats_.inc.bytes = stats.ibytes;
    port_stats_.out.packets = stats.opackets;
    port_stats_.out.bytes = stats.obytes;
  } else {
    dir = PACKET_DIR_INC;
    for (qid = 0; qid < num_queues[dir]; qid++) {
      queue_stats[dir][qid].packets = stats.q_ipackets[qid];
      queue_stats[dir][qid].bytes = stats.q_ibytes[qid];
      queue_stats[dir][qid].dropped = stats.q_errors[qid];
    }

    dir = PACKET_DIR_OUT;
    for (qid = 0; qid < num_queues[dir]; qid++) {
      queue_stats[dir][qid].packets = stats.q_opackets[qid];
      queue_stats[dir][qid].bytes = stats.q_obytes[qid];
    }
  }
}

int PMDPort::RecvPackets(queue_t qid, bess::Packet **pkts, int cnt) {
  return rte_eth_rx_burst(dpdk_port_id_, qid,
                          reinterpret_cast<rte_mbuf **>(pkts), cnt);
}

int PMDPort::SendPackets(queue_t qid, bess::Packet **pkts, int cnt) {
  int sent = rte_eth_tx_burst(dpdk_port_id_, qid,
                              reinterpret_cast<rte_mbuf **>(pkts), cnt);
  auto &stats = queue_stats[PACKET_DIR_OUT][qid];
  int dropped = cnt - sent;
  stats.dropped += dropped;
  stats.requested_hist[cnt]++;
  stats.actual_hist[sent]++;
  stats.diff_hist[dropped]++;
  return sent;
}

Port::LinkStatus PMDPort::GetLinkStatus() {
  rte_eth_link status;
  // rte_eth_link_get() may block up to 9 seconds, so use _nowait() variant.
  rte_eth_link_get_nowait(dpdk_port_id_, &status);

  return LinkStatus{.speed = status.link_speed,
                    .full_duplex = static_cast<bool>(status.link_duplex),
                    .autoneg = static_cast<bool>(status.link_autoneg),
                    .link_up = static_cast<bool>(status.link_status)};
}

ADD_DRIVER(PMDPort, "pmd_port", "DPDK poll mode driver")

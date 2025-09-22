#!/usr/bin/env python3
#
# Copyright (C) 2023 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import argparse

# The following counters should be maintained in order matching ApfCounterTracker.java.
Counter = (
    "TOTAL_PACKETS",
    "DROPPED_802_3_FRAME",
    "DROPPED_ARP_NON_IPV4",
    "DROPPED_ARP_OTHER_HOST",
    "DROPPED_ARP_REPLY_SPA_NO_HOST",
    "DROPPED_ARP_REQUEST_REPLIED",
    "DROPPED_ARP_UNKNOWN",
    "DROPPED_ARP_V6_ONLY",
    "DROPPED_ETH_BROADCAST",
    "DROPPED_ETHER_OUR_SRC_MAC",
    "DROPPED_ETHERTYPE_NOT_ALLOWED",
    "DROPPED_GARP_REPLY",
    "DROPPED_IGMP_INVALID",
    "DROPPED_IGMP_REPORT",
    "DROPPED_IGMP_V2_GENERAL_QUERY_REPLIED",
    "DROPPED_IGMP_V3_GENERAL_QUERY_REPLIED",
    "DROPPED_IPV4_BROADCAST_ADDR",
    "DROPPED_IPV4_BROADCAST_NET",
    "DROPPED_IPV4_ICMP_INVALID",
    "DROPPED_IPV4_KEEPALIVE_ACK",
    "DROPPED_IPV4_L2_BROADCAST",
    "DROPPED_IPV4_MULTICAST",
    "DROPPED_IPV4_NATT_KEEPALIVE",
    "DROPPED_IPV4_NON_DHCP4",
    "DROPPED_IPV4_PING_REQUEST_REPLIED",
    "DROPPED_IPV4_TCP_PORT7_UNICAST",
    "DROPPED_IPV6_ICMP6_ECHO_REQUEST_INVALID",
    "DROPPED_IPV6_ICMP6_ECHO_REQUEST_REPLIED",
    "DROPPED_IPV6_MLD_INVALID",
    "DROPPED_IPV6_MLD_REPORT",
    "DROPPED_IPV6_MLD_V1_GENERAL_QUERY_REPLIED",
    "DROPPED_IPV6_MLD_V2_GENERAL_QUERY_REPLIED",
    "DROPPED_IPV6_MULTICAST_NA",
    "DROPPED_IPV6_NON_ICMP_MULTICAST",
    "DROPPED_IPV6_NS_INVALID",
    "DROPPED_IPV6_NS_OTHER_HOST",
    "DROPPED_IPV6_NS_REPLIED_NON_DAD",
    "DROPPED_IPV6_ROUTER_SOLICITATION",
    "DROPPED_MDNS",
    "DROPPED_MDNS_REPLIED",
    "DROPPED_NON_UNICAST_TDLS",
    "DROPPED_RA",
    "PASSED_ARP_BROADCAST_REPLY",
    "PASSED_ARP_REQUEST",
    "PASSED_ARP_UNICAST_REPLY",
    "PASSED_DHCP",
    "PASSED_DUE_TO_REPLY_OVER_MTU",
    "PASSED_ETHER_OUR_SRC_MAC",
    "PASSED_IPV4",
    "PASSED_IPV4_FROM_DHCPV4_SERVER",
    "PASSED_IPV4_UNICAST",
    "PASSED_IPV6_HOPOPTS",
    "PASSED_IPV6_ICMP",
    "PASSED_IPV6_NON_ICMP",
    "PASSED_IPV6_UNICAST_NON_ICMP",
    "PASSED_LOW_POWER_STANDBY_MAGIC_PACKET",
    "PASSED_MDNS",
    "PASSED_NON_IP_UNICAST",
    "PASSED_RA"
)

def main():
  parser = argparse.ArgumentParser(description='Parse APF counter HEX string.')
  parser.add_argument('hexstring')
  args = parser.parse_args()
  data_hexstring = args.hexstring
  data_bytes = bytes.fromhex(data_hexstring)
  data_bytes_len = len(data_bytes)
  for i in range(len(Counter)):
    cnt = int.from_bytes(data_bytes[data_bytes_len - 4 * (i + 1) :
                                    data_bytes_len - 4 * i], byteorder = "big")
    if cnt != 0:
      print("{} : {}".format(Counter[i], cnt))

if __name__ == "__main__":
  main()

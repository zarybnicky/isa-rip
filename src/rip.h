/*
 * ISA18: Tools for monitoring and sniffing RIP messages
 * FIT VUT Brno
 * Author: xzaryb00 - Jakub Zarybnický (xzaryb00)
 */

#ifndef ISA_RIP_H
#define ISA_RIP_H

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#define RIP_FILTER "portrange 520-521 and udp"
#define RIP_CMD_REQUEST 1
#define RIP_CMD_RESPONSE 2
#define RIP_CMD_TRACEON 3
#define RIP_CMD_TRACEOFF 4
#define RIP_UNREACHABLE 16
#define RIP_AUTH 0xffff
#define RIP_AUTH_MD5 3
#define RIP_AUTH_MD5_TRAILER 1
#define RIP_AUTH_PASS 2
#define RIPNG_NEXT_HOP 0xff
#define	RIPNG_DEST "ff02::9"
#define RIPNG_PORT 521
#define RIPNG_PORT_STR "521"

struct riphdr {
  u_char rip_cmd;
  u_char rip_ver;
  u_short rip_domain;
};

struct rip_entry {
  u_short rip_family;
  u_short rip_tag;
  union {
    struct {
      struct in_addr rip_dest;
      struct in_addr rip_mask;
      struct in_addr rip_next_hop;
      u_int32_t rip_metric;
    };
    struct {
      u_short rip_packet_len;
      u_char rip_key_id;
      u_char rip_auth_len;
      u_int32_t rip_seq;
      u_int32_t rip_zeros;
      u_int32_t rip_zeros2;
    };
    u_char rip_pass[16];
  } body;
};

struct rip6hdr {
  u_char rip6_cmd;
  u_char rip6_ver;
  u_short rip6_zeros;
};

struct rip6_entry {
  struct in6_addr rip6_dest;
  u_short rip6_tag;
  u_char rip6_prefix;
  u_char rip6_metric;
};

/**
 * Return the string representation of a RIP command constant
 */
static inline const char *rip_cmd(u_char cmd) {
  switch (cmd) {
  case RIP_CMD_REQUEST:  return "Request";
  case RIP_CMD_RESPONSE: return "Response";
  case RIP_CMD_TRACEON:  return "Traceon";
  case RIP_CMD_TRACEOFF: return "Traceoff";
  default:               return "(unknown)";
  }
}

/**
 * Return the string representation of the number of hops in RIP
 *
 * (Yes, this is an ugly hack, but better than malloc-ing a string.)
 */
static inline const char *rip_hops(u_char hops) {
  switch (hops) {
  case RIP_UNREACHABLE: return "unreach";
  case 15:              return "15 hops";
  case 14:              return "14 hops";
  case 13:              return "13 hops";
  case 12:              return "12 hops";
  case 11:              return "11 hops";
  case 10:              return "10 hops";
  case  9:              return "9 hops";
  case  8:              return "8 hops";
  case  7:              return "7 hops";
  case  6:              return "6 hops";
  case  5:              return "5 hops";
  case  4:              return "4 hops";
  case  3:              return "3 hops";
  case  2:              return "2 hops";
  case  1:              return "1 hops";
  case  0:              return "0 hops";
  default:              return "unknown";
  }
}

#endif //ISA_RIP_H

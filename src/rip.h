/*
 * ISA18: Tools for monitoring and sniffing RIP messages
 * FIT VUT Brno
 * Author: xzaryb00 - Jakub Zarybnický (xzaryb00)
 */

#ifndef ISA_RIP_H
#define ISA_RIP_H

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
 * Return the string description of a RIP command constant
 */
static inline const char *rip_cmd(u_char cmd) {
  switch (cmd) {
  case RIP_CMD_REQUEST:
    return "Request";
  case RIP_CMD_RESPONSE:
    return "Response";
  case RIP_CMD_TRACEON:
    return "Traceon";
  case RIP_CMD_TRACEOFF:
    return "Traceoff";
  default:
    return "(unknown)";
  }
}

#endif //ISA_RIP_H

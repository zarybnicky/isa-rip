#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include "rip.h"

#define USAGE "Usage: %s -i INTERFACE -r IPv6/MASK [-n IPv6] [-m METRIC] [-t TAG]\n"

int main (int argc, char *argv[]) {
  int opt;
  char *interface = NULL,
    *opt_network = NULL,
    *opt_next_hop = NULL,
    *opt_metric = NULL,
    *opt_tag = NULL;

  while ((opt = getopt(argc, argv, "i:r:n:m:t:")) != -1) {
    switch (opt) {
    case 'i':
      interface = optarg;
      break;
    case 'r':
      opt_network = optarg;
      break;
    case 'n':
      opt_next_hop = optarg;
      break;
    case 'm':
      opt_metric = optarg;
      break;
    case 't':
      opt_tag = optarg;
      break;
    default:
      fprintf(stderr, USAGE, argv[0]);
      exit(EXIT_FAILURE);
    }
  }
  if (interface == NULL) {
    fprintf(stderr, "Missing required option `-i interface`\n");
    fprintf(stderr, USAGE, argv[0]);
    exit(EXIT_FAILURE);
  }
  if (opt_network == NULL) {
    fprintf(stderr, "Missing required option `-r IPv6/MASK`\n");
    fprintf(stderr, USAGE, argv[0]);
    exit(EXIT_FAILURE);
  }
  if (opt_next_hop == NULL) {
    opt_next_hop = "::";
  }
  if (opt_metric == NULL) {
    opt_metric = "1";
  }
  if (opt_tag == NULL) {
    opt_tag = "0";
  }

  struct addrinfo hints = { .ai_family = AF_INET6, .ai_socktype = SOCK_DGRAM };
  struct addrinfo *result, *rp;

  char dest[256] = { RIPNG_DEST "%" };
  strcat(dest, interface);
  int s = getaddrinfo(dest, "521", &hints, &result);
  if (s != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    exit(EXIT_FAILURE);
  }
  int sock;
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sock == -1) {
      continue;
    }
    if (bind(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
      break;
    }
  }
  if (rp == NULL) {
    fprintf(stderr, "Failed to find an interface\n");
    exit(EXIT_FAILURE);
  }
  freeaddrinfo(result);

  //Bind to the right interface and set multicast
  uint ifindex = if_nametoindex(interface);
  if (ifindex == 0) {
    perror("if_nametoindex()");
    close(sock);
    exit(EXIT_FAILURE);
  }
  if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0) {
    perror("setsockopt(IPV6_MULTICAST_IF)");
    close(sock);
    exit(EXIT_FAILURE);
  }

  //Create the multicast address
  struct sockaddr_in6 target;
  inet_pton(AF_INET6, RIPNG_DEST, &target.sin6_addr);
  target.sin6_family = AF_INET6;
  target.sin6_port = htons(RIPNG_PORT);
  target.sin6_flowinfo = 0;
  target.sin6_scope_id = 0;

  char buffer[512] = {};
  uint buflen = 0;

  struct rip6hdr header = { .rip6_cmd = RIP_CMD_RESPONSE, .rip6_ver = 1 };
  memcpy(buffer, &header, sizeof(header));
  buflen += sizeof(header);

  struct rip6_entry entry = {};
  struct in6_addr network;
  char *prefix, *prefix_err;
  prefix = strchr(opt_network, '/');
  if (prefix == NULL) {
    fprintf(stderr, "The separator slash is missing in the specified network\n");
    exit(EXIT_FAILURE);
  }
  prefix[0] = '\0';
  prefix += 1;
  if (inet_pton(AF_INET6, opt_network, &network) < 1) {
    fprintf(stderr, "The specified network doesn't contain a valid IPv6 address\n");
    exit(EXIT_FAILURE);
  }
  entry.rip6_dest = network;
  entry.rip6_prefix = strtol(prefix, &prefix_err, 10);
  if (*prefix_err != '\0') {
    fprintf(stderr, "The specified prefix isn't a valid number\n");
    exit(EXIT_FAILURE);
  }
  memcpy(buffer + buflen, &entry, sizeof(entry));
  buflen += sizeof(entry);

  struct rip6_entry next_hop = { .rip6_metric = RIPNG_NEXT_HOP };
  memcpy(buffer + buflen, &next_hop, sizeof(next_hop));
  buflen += sizeof(next_hop);


  if (sendto(sock, buffer, buflen, 0, (struct sockaddr *) &target, sizeof(target)) < 0) {
    perror("sendto()");
    close(sock);
    exit(EXIT_FAILURE);
  }

  return 0;
}

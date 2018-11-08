#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "rip.h"

#define USAGE "Usage: %s -i INTERFACE -r IPv6/MASK [-n IPv6] [-m METRIC] [-t TAG]\n"
#define ERR_USAGE(...)                             \
  do {                                           \
    fprintf(stderr, USAGE, argv[0]);             \
    ERR(__VA_ARGS__);                            \
  } while(0);
#define ERR(...) do {                              \
    fprintf(stderr, __VA_ARGS__);                \
    exit(EXIT_FAILURE);                          \
  } while(0);
#define SOCK_WRAP(sock, err, cond)               \
  if (cond) {                                    \
    perror("if_nametoindex()");                  \
    close(sock);                                 \
    exit(EXIT_FAILURE);                          \
  }

int main (int argc, char *argv[]) {
  int opt, tmp;
  char *prefix = NULL, *err = NULL, *interface = NULL;

  struct rip6hdr header = { .rip6_cmd = RIP_CMD_RESPONSE, .rip6_ver = 1 };
  struct rip6_entry entry = { .rip6_metric = 1 };
  struct rip6_entry next_hop = { .rip6_metric = RIPNG_NEXT_HOP };

  while ((opt = getopt(argc, argv, "i:r:n:m:t:")) != -1) {
    switch (opt) {
    case 'i':
      //Interface processing (getaddrinfo) happens later
      interface = optarg;
      break;

    case 'r':
      //Split optarg at forward slash
      prefix = strchr(optarg, '/');
      if (prefix == NULL)
        ERR("The separator slash is missing in the specified network\n");
      prefix[0] = '\0';
      prefix += 1;
      //Now the \0-terminated address is in `optarg` and prefix is in `prefix`

      //Parse the IPv6 address
      if (inet_pton(AF_INET6, optarg, &entry.rip6_dest) < 1)
        ERR("The specified network doesn't contain a valid IPv6 address\n");

      //Parse prefix
      tmp = strtol(prefix, &err, 10);
      if (*err != '\0')
        ERR("The specified prefix isn't a valid number\n");
      if (tmp < 0 || tmp > 128)
        ERR("The specified prefix is out of range (0-128)\n");
      entry.rip6_prefix = tmp;
      break;

    case 'n':
      //Parse the next hop
      if (inet_pton(AF_INET6, optarg, &next_hop.rip6_dest) < 1)
        ERR("The specified next hop doesn't contain a valid IPv6 address\n");
      break;

    case 'm':
      //Parse the metric
      tmp = strtol(optarg, &err, 10);
      if (*err != '\0')
        ERR("The specified metric isn't a valid number\n");
      if (tmp < 0 || (tmp > 16 && tmp != 255))
        ERR("The specified metric is out of range (0-16)\n");
      entry.rip6_metric = tmp;
      break;

    case 't':
      //Parse the tag
      tmp = htons(strtol(optarg, &err, 10));
      if (*err != '\0')
        ERR("The specified tag isn't a valid number\n");
      if (tmp < 0 || tmp > 65535)
        ERR("The specified tag is out of range (0-65535)\n");
      entry.rip6_tag = tmp;
      break;

    default:
      fprintf(stderr, USAGE, argv[0]);
      exit(EXIT_FAILURE);
    }
  }
  if (interface == NULL)
    ERR_USAGE("Missing required option `-i interface`\n");
  if (prefix == NULL)
    ERR_USAGE("Missing required option `-r IPv6/MASK`\n");

  //Craft the target addr: ff02::9%iface
  char dest[256] = { RIPNG_DEST "%" };
  strcat(dest, interface);

  //Try to find suitable parameters for the sending socket, so that it it:
  //IPv6, UDP, multicast-enabled, able to reach ff02::9%iface at port 521
  struct addrinfo hints = { .ai_family = AF_INET6, .ai_socktype = SOCK_DGRAM };
  struct addrinfo *result, *rp;
  int sock;
  int s = getaddrinfo(dest, RIPNG_PORT_STR, &hints, &result);
  if (s != 0)
    ERR("getaddrinfo: %s\n", gai_strerror(s))
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    //Try this candidate addrinfo
    sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sock == -1) {
      perror("socket");
      continue;
    }

    char buffer[INET6_ADDRSTRLEN];
    if (getnameinfo((struct sockaddr *) rp->ai_addr, rp->ai_addrlen,
                    buffer, sizeof(buffer), 0, 0, NI_NUMERICHOST) != 0) {
      perror("getnameinfo");
      exit(EXIT_FAILURE);
    }
    printf("Binding to port %d at %s\n",
           ntohs(((struct sockaddr_in6 *) rp->ai_addr)->sin6_port), buffer);

    //Bind to the privileged source port 521 - this requires root
    if (bind(sock, rp->ai_addr, rp->ai_addrlen) != 0) {
      perror("bind");
      continue;
    }
    break; //Got it, both socket() and bind() succeeded
  }
  if (rp == NULL) {
    ERR("Failed to find an interface or to bind to one\n");
  }
  freeaddrinfo(result);

  //Find iface index and set MULTICAST_IF and _HOPS
  uint ifindex = if_nametoindex(interface);
  SOCK_WRAP(sock, "if_nametoindex()", ifindex == 0);
  SOCK_WRAP(sock, "setsockopt(IPV6_MULTICAST_IF)",
            setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0);
  uint hops = 255;
  SOCK_WRAP(sock, "setsockopt(IPV6_MULTICAST_HOPS)",
            setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0);

  //Copy all three parts into the buffer
  char buffer[512] = { 0 };
  uint buflen = 0;
  memcpy(buffer, &header, sizeof(header));
  buflen += sizeof(header);
  if (!IN6_IS_ADDR_UNSPECIFIED(&next_hop.rip6_dest)) {
    //We only need to send next hop if it's non-zero, as zero (originator) is the
    //implicit next hop
    memcpy(buffer + buflen, &next_hop, sizeof(next_hop));
    buflen += sizeof(next_hop);
  }
  memcpy(buffer + buflen, &entry, sizeof(entry));
  buflen += sizeof(entry);

  //Create the multicast address
  struct sockaddr_in6 target;
  inet_pton(AF_INET6, RIPNG_DEST, &target.sin6_addr);
  target.sin6_family = AF_INET6;
  target.sin6_port = htons(RIPNG_PORT);
  target.sin6_flowinfo = 0;
  target.sin6_scope_id = 0;

  printf("Sending message... ");
  SOCK_WRAP(sock, "sendto()",
            sendto(sock, buffer, buflen, 0, (struct sockaddr *) &target, sizeof(target)) < 0);
  printf("OK\n");
  return 0;
}

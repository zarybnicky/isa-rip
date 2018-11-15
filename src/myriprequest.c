/**
 * ISA18: Tools for monitoring and sniffing RIP messages
 * FIT VUT Brno
 * Author: xzaryb00 - Jakub Zarybnický (xzaryb00)
 *
 * A program that multicasts a RIPng Request packet
 */

#include "myriprequest.h"
#define USAGE "Usage: %s -i INTERFACE [-r IPv6/MASK]"

int main (int argc, char *argv[]) {
  int opt;
  char *interface = NULL;

  struct rip6hdr header = { .rip6_cmd = RIP_CMD_REQUEST, .rip6_ver = 1 };
  struct rip6_entry entry = { .rip6_metric = 16 };

  while ((opt = getopt(argc, argv, "i:r:")) != -1) {
    switch (opt) {
    case 'i': //Interface
      interface = optarg;
      break;
    case 'r': //Address and prefix
      parse_address_mask(optarg, &entry.rip6_dest, &entry.rip6_prefix);
      break;
    default:
      fprintf(stderr, USAGE, argv[0]);
      exit(EXIT_FAILURE);
    }
  }
  if (interface == NULL)
    ERR_USAGE("Missing required option `-i INTERFACE`\n");

  //Copy both parts into the buffer
  char buffer[512] = { 0 };
  uint buflen = 0;
  memcpy(buffer, &header, sizeof(header));
  buflen += sizeof(header);
  memcpy(buffer + buflen, &entry, sizeof(entry));
  buflen += sizeof(entry);

  struct sockaddr_in6 target = { .sin6_family = AF_INET6,
                                 .sin6_port = htons(RIPNG_PORT),
                                 .sin6_flowinfo = 0 };
  inet_pton(AF_INET6, RIPNG_DEST, &target.sin6_addr);

  int sock = prepare_socket(interface);

  printf("Sending message... ");
  SOCK_WRAP(sock, "sendto()",
            sendto(sock, buffer, buflen, 0, (struct sockaddr *) &target, sizeof(target)) < 0);
  printf("OK\n");
  return 0;
}

/**
 * ISA18: Tools for monitoring and sniffing RIP messages
 * FIT VUT Brno
 * Author: xzaryb00 - Jakub Zarybnický (xzaryb00)
 *
 * A program that multicasts a RIPng Response packet
 */

#include "myripresponse.h"
#define USAGE "Usage: %s -i INTERFACE -r IPv6/MASK [-n IPv6] [-m METRIC] [-t TAG]\n"

int main(int argc, char *argv[]) {
  int opt;
  char *prefix = NULL, *interface = NULL;

  struct rip6hdr header = { .rip6_cmd = RIP_CMD_RESPONSE, .rip6_ver = 1 };
  struct rip6_entry entry = { .rip6_metric = 1 };
  struct rip6_entry next_hop = { .rip6_metric = RIPNG_NEXT_HOP };

  //Argument processing
  while ((opt = getopt(argc, argv, "i:r:n:m:t:")) != -1) {
    switch (opt) {
    case 'r': //Address and prefix
      //Split optarg at forward slash
      prefix = strchr(optarg, '/');
      if (prefix == NULL)
        ERR("The separator slash is missing in the specified network\n");
      prefix[0] = '\0';
      prefix += 1;
      //Now the \0-terminated address is in `optarg` and prefix is in `prefix`
      if (inet_pton(AF_INET6, optarg, &entry.rip6_dest) < 1)
        ERR("The specified network doesn't contain a valid IPv6 address\n");
      entry.rip6_prefix = parse_number("prefix", prefix, 0, 128);
      break;

    case 'i': //Interface (parsing happens later)
      interface = optarg;
      break;
    case 'n': //Next hop
      if (inet_pton(AF_INET6, optarg, &next_hop.rip6_dest) < 1)
        ERR("The specified next hop doesn't contain a valid IPv6 address\n");
      break;
    case 'm': //Metric
      entry.rip6_metric = parse_number("metric", optarg, 0, 255);
      break;
    case 't': //Tag
      entry.rip6_tag = htons(parse_number("tag", optarg, 0, 65535));
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


/**
 * Parse an integer with a range check (exits on error)
 */
int parse_number(const char *desc, const char *src, int lower, int upper) {
  char *err = NULL;
  int result = strtol(src, &err, 10);
  if (*err != '\0')
    ERR("The specified %s isn't a valid number\n", desc);
  if (result < lower || result > upper)
    ERR("The specified %s is out of range (%d-%d)\n", desc, lower, upper);
  return result;
}

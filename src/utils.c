/**
 * ISA18: Tools for monitoring and sniffing RIP messages
 * FIT VUT Brno
 * Author: xzaryb00 - Jakub Zarybnický (xzaryb00)
 *
 * A set of utilities used throughout all three programs
 */

#include "utils.h"

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

/**
 * Parse slash-separated IPv6 address and a numeric network mask
 * Mutates `optarg`.
 */
void parse_address_mask(char *optarg, struct in6_addr *addr, u_char *mask) {
  //Split optarg at forward slash
  char *prefix = strchr(optarg, '/');
  if (prefix == NULL)
    ERR("The separator slash is missing in the specified network\n");
  prefix[0] = '\0';
  prefix += 1;
  //Now the \0-terminated address is in `optarg` and prefix is in `prefix`
  if (inet_pton(AF_INET6, optarg, addr) < 1)
    ERR("The specified network doesn't contain a valid IPv6 address\n");
  *mask = parse_number("prefix", prefix, 0, 128);
}

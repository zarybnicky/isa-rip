/**
 * ISA18: Tools for monitoring and sniffing RIP messages
 * FIT VUT Brno
 * Author: xzaryb00 - Jakub Zarybnický (xzaryb00)
 *
 * A utility for creating a RIP multicast socket
 */

#include "socket.h"

/**
 * Prepares an IPv6 UDP socket so that it's able to multicast via the specified
 * interface.
 */
int prepare_socket(const char *interface) {
  //Craft the target addr `ff02::9%iface`
  char dest[256] = { RIPNG_DEST "%" };
  strcat(dest, interface);

  //Try to find suitable parameters for the sending socket, so that it it:
  //IPv6, UDP, multicast-enabled, able to reach ff02::9%iface at port 521
  struct addrinfo hints = { .ai_family = AF_INET6, .ai_socktype = SOCK_DGRAM };
  struct addrinfo *result, *rp;
  int sock;
  int s = getaddrinfo(dest, RIPNG_PORT_STR, &hints, &result);
  if (s != 0)
    ERR("getaddrinfo: %s\n", gai_strerror(s));

  //Iterate through all returned `addrinfo`s
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sock == -1) {
      perror("socket");
      continue;
    }

    //Logging the port and address we'll bind to
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

  return sock;
}

/**
 * ISA18: Tools for monitoring and sniffing RIP messages
 * FIT VUT Brno
 * Author: xzaryb00 - Jakub Zarybnický (xzaryb00)
 *
 * Sniffer for RIP/RIPng using libpcap
 */

#include "myripsniffer.h"
#define USAGE "Usage: %s -i INTERFACE\n"

int main (int argc, char *argv[]) {
  int opt;
  char *interface = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];

  while ((opt = getopt(argc, argv, "i:")) != -1) {
    switch (opt) {
    case 'i':
      interface = optarg;
      break;
    default:
      fprintf(stderr, USAGE, argv[0]);
      exit(EXIT_FAILURE);
    }
  }
  if (interface == NULL)
    ERR_USAGE("Missing required option `-i INTERFACE`\n");

  //Find out the parameters of the selected interface
  bpf_u_int32 addr, mask;
  if (pcap_lookupnet(interface, &addr, &mask, errbuf) == -1)
    ERR("pcap_lookupnet: %s\n", errbuf);

  //Opening the device
  pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL)
    ERR("pcap_open_live: %s\n", errbuf);

  //Compiling and setting the filter (RIP_FILTER)
  struct bpf_program filter;
  if (pcap_compile(handle, &filter, RIP_FILTER, 0, addr) == -1)
    ERR("pcap_compile: %s\n", pcap_geterr(handle));
  if (pcap_setfilter(handle, &filter) == -1)
    ERR("pcap_setfilter: %s\n", pcap_geterr(handle));

  //And kicking off the sniffer
  fprintf(stderr, "Listening...\n");
  if (pcap_loop(handle, -1, sniff_handler, NULL) == -1)
    ERR("pcap_loop: %s\n", pcap_geterr(handle));

  pcap_close(handle);
  return 0;
}

/**
 * Handle a captured packet - process and print Ethernet, IP, and UDP headers &
 * pass RIP contents on
 */
void sniff_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  (void) args;
  struct ether_header *eptr = (struct ether_header *) packet;
  struct ip *ip;
  struct ip6_hdr *ip6;
  struct udphdr *udp;
  char time[30], addr[INET6_ADDRSTRLEN];
  strftime(time, 30, "%F %T", localtime((time_t *) &header->ts.tv_sec));

  switch (ntohs(eptr->ether_type)) {
  case ETHERTYPE_IP: // IPv4
    ip = (struct ip *) (packet + sizeof(struct ether_header));
    udp = (struct udphdr *) (((u_char *) ip) + sizeof(struct ip));
    if (ip->ip_p != IPPROTO_UDP) {
      return;
    }
    printf("[%s] from %s at port %d to port %d\n",
           time, inet_ntoa(ip->ip_src), ntohs(udp->uh_sport), ntohs(udp->uh_dport));
    print_rip_packet(ntohs(udp->uh_ulen) - sizeof(struct udphdr),
                     (struct riphdr *) (((u_char *) udp) + sizeof(struct udphdr)));
    printf("\n");
    break;

  case ETHERTYPE_IPV6: //IPv6
    ip6 = (struct ip6_hdr *) (packet + sizeof(struct ether_header));
    udp = (struct udphdr *) (((u_char *) ip6) + sizeof(struct ip6_hdr));
    if (ip6->ip6_nxt != IPPROTO_UDP) {
      //Ignoring messages with IPv6 extensions
      return;
    }
    printf("[%s] from %s at port %d to port %d\n",
           time, inet_ntop(AF_INET6, &ip6->ip6_src, addr, INET6_ADDRSTRLEN),
           ntohs(udp->uh_sport), ntohs(udp->uh_dport));
    print_ripng_packet(ntohs(udp->uh_ulen) - sizeof(struct udphdr),
                       (struct rip6hdr *) (((u_char *) udp) + sizeof(struct udphdr)));
    printf("\n");
    break;

  default: // Ignore all other
    break;
  }
}

/**
 * Handle a captured RIP packet - print the header line and iterate through entries
 */
void print_rip_packet(size_t riplen, struct riphdr *rip) {
  struct rip_entry *rip_entry = (struct rip_entry *) (((u_char *) rip) + sizeof(struct riphdr));
  u_int entries = (riplen - sizeof(struct riphdr)) / sizeof(struct rip_entry);

  //RIPng header
  printf("RIPv%d %s with %d items", rip->rip_ver, rip_cmd(rip->rip_cmd), entries);
  if (rip->rip_ver == 2) {
    printf(", domain %d", rip->rip_domain);
  }
  printf("\n");

  //Semantics of the packet
  if (entries == 1 &&
      ntohs(rip_entry->rip_family) == 0 &&
      ntohl(rip_entry->body.rip_metric) == RIP_UNREACHABLE) {
    printf("Request for the whole routing table\n");
  }

  //Dump the entries
  for (; entries > 0; entries -= 1, rip_entry++) {
    if (rip->rip_ver == 2) {
      print_ripv2_entry(rip_entry);
    } else {
      print_ripv1_entry(rip_entry);
    }
  }
}

/**
 * Print out a single RIPv1 entry
 */
void print_ripv1_entry(struct rip_entry *e) {
  printf("%8s,           %s",
         rip_hops(ntohl(e->body.rip_metric)), inet_ntoa(e->body.rip_dest));
  if (ntohs(e->rip_family) != AF_INET) {
    printf(" (family %d)", ntohs(e->rip_family));
  }
  printf("\n");
}

/**
 * Print out a single RIPv2 entry
 */
void print_ripv2_entry(struct rip_entry *e) {
  switch (ntohs(e->rip_family)) {
  case RIP_AUTH: //Auth entry
    switch (ntohs(e->rip_tag)) {
    case RIP_AUTH_PASS:
      printf("Auth type: password Password: %s\n", e->body.rip_pass);
      break;
    case RIP_AUTH_MD5:
      printf("Auth type: keyed    Preface: offset: %u, key ID %u, auth len %u, seq %u\n",
             ntohs(e->body.rip_packet_len), e->body.rip_key_id,
             e->body.rip_auth_len, ntohl(e->body.rip_seq));
      break;
    case RIP_AUTH_MD5_TRAILER:
      printf("Auth type: keyed    Trailer: ");
      for (u_short i = 0; i < 16; i++) {
        printf("%02x", e->body.rip_pass[i]);
      }
      printf("\n");
      break;
    default:
      printf("Auth type: unknown\n");
      break;
    }
    break;
  default: //AF_INET and others
    printf("%8s, tag %-5u %s/",
           rip_hops(ntohl(e->body.rip_metric)), ntohs(e->rip_tag),
           inet_ntoa(e->body.rip_dest));
    printf("%s", inet_ntoa(e->body.rip_mask));
    if (e->body.rip_next_hop.s_addr != 0) {
      printf(" -> %s", inet_ntoa(e->body.rip_next_hop));
    }
    if (ntohs(e->rip_family) != AF_INET) {
      printf(" (family %d)", ntohs(e->rip_family));
    }
    printf("\n");
    break;
  }
}

/**
 * Handle a captured RIPng packet - print the header line and iterate through entries
 */
void print_ripng_packet(size_t riplen, struct rip6hdr *rip6) {
  struct rip6_entry *rip6_entry = (struct rip6_entry *) (((u_char *) rip6) + sizeof(struct rip6hdr));
  u_int entries = (riplen - sizeof(struct rip6hdr)) / sizeof(struct rip6_entry);

  //RIP header
  printf("RIPng %s with %d items\n", rip_cmd(rip6->rip6_cmd), entries);

  //Semantics of the packet
  if (entries == 1 &&
      rip6_entry->rip6_tag == 0 &&
      rip6_entry->rip6_metric == RIP_UNREACHABLE &&
      IN6_IS_ADDR_UNSPECIFIED(&rip6_entry->rip6_dest)) {
    printf("Request for the whole routing table\n");
  }

  //Dump the entries
  for (; entries > 0; entries -= 1, rip6_entry++) {
    print_ripng_entry(rip6_entry);
  }
}

/**
 * Print out a single RIPng entry
 */
void print_ripng_entry(struct rip6_entry *e) {
  char addr[INET6_ADDRSTRLEN];
  if (e->rip6_metric == RIPNG_NEXT_HOP) {
    printf("Next hop for the following entries: %s\n",
           inet_ntop(AF_INET6, &e->rip6_dest, addr, INET6_ADDRSTRLEN));
    return;
  }
  printf("%8s, tag %-5u %s/%d\n",
         rip_hops(e->rip6_metric), ntohs(e->rip6_tag),
         inet_ntop(AF_INET6, &e->rip6_dest, addr, INET6_ADDRSTRLEN),
         e->rip6_prefix);
}

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include "rip.h"

void print_ripv1_entry(struct rip_entry *e) {
  if (ntohl(e->body.rip_metric) == RIP_UNREACHABLE) {
    printf("unreachable");
  } else {
    printf("%5u hops, ", ntohl(e->body.rip_metric));
  }
  printf("           %s", inet_ntoa(e->body.rip_dest));
  if (ntohs(e->rip_family) != AF_INET) {
    printf(" (family %d)", ntohs(e->rip_family));
  }
  printf("\n");
}

void print_ripv2_entry(struct rip_entry *e) {
  if (ntohs(e->rip_family) == RIP_AUTH) {
    if (ntohs(e->rip_tag) == RIP_AUTH_PASS) {
      printf("Auth type: password   Password: %s\n", e->body.rip_pass);
    } else if (ntohs(e->rip_tag) == RIP_AUTH_MD5) {
      printf("Auth type: keyed      Preface: offset: %u, key ID %u, auth len %u, seq %u\n",
             ntohs(e->body.rip_packet_len), e->body.rip_key_id,
             e->body.rip_auth_len, ntohl(e->body.rip_seq));
    } else if (ntohs(e->rip_tag) == RIP_AUTH_MD5_TRAILER) {
      printf("Auth type: keyed      Trailer: ");
      for (u_short i = 0; i < 16; i++) {
        printf("%02x", e->body.rip_pass[i]);
      }
      printf("\n");
    } else {
      printf("Auth type: unknown\n");
    }
    return;
  }
  if (ntohl(e->body.rip_metric) == RIP_UNREACHABLE) {
    printf("unreachable");
  } else {
    printf("%5u hops, ", ntohl(e->body.rip_metric));
  }
  printf("tag %-5u %s", ntohs(e->rip_tag), inet_ntoa(e->body.rip_dest));
  printf("/%s", inet_ntoa(e->body.rip_mask));
  printf(" -> %s", inet_ntoa(e->body.rip_next_hop));
  if (e->body.rip_next_hop.s_addr == 0) {
    printf(" (originator)");
  }
  if (ntohs(e->rip_family) != AF_INET) {
    printf(" (family %d)", ntohs(e->rip_family));
  }
  printf("\n");
}

void print_ripng_entry(struct rip6_entry *e) {
  char addr[INET6_ADDRSTRLEN];
  if (e->rip6_metric == RIPNG_NEXT_HOP) {
    printf("            next hop: %s\n",
           inet_ntop(AF_INET6, &e->rip6_dest, addr, INET6_ADDRSTRLEN));
    return;
  }
  if (e->rip6_metric == RIP_UNREACHABLE) {
    printf("unreachable ");
  } else {
    printf("%5u hops, ", e->rip6_metric);
  }
  printf("tag %-5u %s/%d\n",
         ntohs(e->rip6_tag),
         inet_ntop(AF_INET6, &e->rip6_dest, addr, INET6_ADDRSTRLEN),
         e->rip6_prefix);
}

void print_rip_packet(time_t *time, struct ip *ip) {
  if (ip->ip_p != IPPROTO_UDP) {
    return;
  }
  struct udphdr *udp = (struct udphdr *) (((u_char *) ip) + ip->ip_hl * 4);
  struct riphdr *rip = (struct riphdr *) (((u_char *) udp) + sizeof(struct udphdr));
  struct rip_entry *rip_entry = (struct rip_entry *) (((u_char *) rip) + sizeof(struct riphdr));
  u_int riplen = ntohs(udp->uh_ulen) - sizeof(struct udphdr);
  u_int entries = (riplen - sizeof(struct riphdr)) / sizeof(struct rip_entry);

  //Header: version, command, number of entries, (domain), source addr, time received
  printf("RIPv%d %-10s %4d items", rip->rip_ver, rip_cmd(rip->rip_cmd), entries);
  if (rip->rip_ver == 2) {
    printf(", domain %-4d %15s    %s", rip->rip_domain, inet_ntoa(ip->ip_src), ctime(time));
  } else {
    printf(" %28s    %s", inet_ntoa(ip->ip_src), ctime(time));
  }

  //Semantics of the packet
  if (entries == 1 &&
      ntohs(rip_entry->rip_family) == 0 &&
      ntohl(rip_entry->body.rip_metric) == RIP_UNREACHABLE) {
    printf("   (request for the whole routing table)\n");
  }

  //Dumping the entries
  for (; entries > 0; entries -= 1, rip_entry++) {
    if (rip->rip_ver == 2) {
      print_ripv2_entry(rip_entry);
    } else {
      print_ripv1_entry(rip_entry);
    }
  }
  printf("\n");
}

void print_ripng_packet(time_t *time, struct ip6_hdr *ip6) {
  if (ip6->ip6_nxt != IPPROTO_UDP) {
    //Ignoring IPv6 extensions
    return;
  }
  struct udphdr *udp = (struct udphdr *) (((u_char *) ip6) + sizeof(struct ip6_hdr));
  struct rip6hdr *rip6 = (struct rip6hdr *) (((u_char *) udp) + sizeof(struct udphdr));
  struct rip6_entry *rip6_entry = (struct rip6_entry *) (((u_char *) rip6) + sizeof(struct rip6hdr));
  u_int riplen = ntohs(udp->uh_ulen) - sizeof(struct udphdr);
  u_int entries = (riplen - sizeof(struct rip6hdr)) / sizeof(struct rip6_entry);
  char addr[INET6_ADDRSTRLEN];

  //Header: version, command, number of entries, source addr, time received
  printf("RIPng %-8s %6d items %28s    %s",
         rip_cmd(rip6->rip6_cmd),
         entries,
         inet_ntop(AF_INET6, &ip6->ip6_src, addr, INET6_ADDRSTRLEN),
         ctime(time));

  //Semantics of the packet
  if (entries == 1 &&
      rip6_entry->rip6_tag == 0 &&
      rip6_entry->rip6_metric == RIP_UNREACHABLE &&
      IN6_IS_ADDR_UNSPECIFIED(&rip6_entry->rip6_dest)) {
    printf("   (request for the whole routing table)\n");
  }

  //Dumping the entries
  for (; entries > 0; entries -= 1, rip6_entry++) {
    print_ripng_entry(rip6_entry);
  }
  printf("\n");
}

void sniff_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  (void) args;
  struct ether_header *eptr = (struct ether_header *) packet;

  switch (ntohs(eptr->ether_type)) {
  case ETHERTYPE_IP:
    print_rip_packet((time_t *) &header->ts.tv_sec,
                     (struct ip *) (packet + sizeof(struct ether_header)));
    break;

  case ETHERTYPE_IPV6:
    print_ripng_packet((time_t *) &header->ts.tv_sec,
                       (struct ip6_hdr *) (packet + sizeof(struct ether_header)));
    break;
  }
}

void usage(char *argv[]) {
  fprintf(stderr, "Usage: %s -i INTERFACE\n", argv[0]);
}

int main (int argc, char *argv[]) {
  int opt;
  char *interface = NULL;

  while ((opt = getopt(argc, argv, "i:")) != -1) {
    switch (opt) {
    case 'i':
      interface = optarg;
      break;
    default:
      usage(argv);
      exit(EXIT_FAILURE);
    }
  }
  if (interface == NULL) {
    fprintf(stderr, "Missing required option `-i INTERFACE`\n");
    usage(argv);
    exit(EXIT_FAILURE);
  }

  char errbuf[PCAP_ERRBUF_SIZE];  // constant defined in pcap.h
  bpf_u_int32 netaddr;            // network address configured at the input device
  bpf_u_int32 mask;               // network mask of the input device
  if (pcap_lookupnet(interface, &netaddr, &mask, errbuf) == -1) {
    fprintf(stderr, "pcap_lookupnet() failed: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  struct bpf_program filter;
  if (pcap_compile(handle, &filter, RIP_FILTER, 0, netaddr) == -1) {
    fprintf(stderr, "pcap_compile() failed: %s\n", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(handle, &filter) == -1) {
    fprintf(stderr, "pcap_setfilter() failed: %s\n", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  fprintf(stderr, "Listening...\n");
  if (pcap_loop(handle, -1, sniff_handler, NULL) == -1) {
    fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  pcap_close(handle);
  return 0;
}

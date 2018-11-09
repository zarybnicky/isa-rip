/*
 * ISA18: Tools for monitoring and sniffing RIP messages
 * FIT VUT Brno
 * Author: xzaryb00 - Jakub Zarybnický (xzaryb00)
 */

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
#include "utils.h"

#define USAGE "Usage: %s -i INTERFACE\n"

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

void print_rip_packet(struct tm *timeinfo, struct ip *ip) {
  if (ip->ip_p != IPPROTO_UDP) {
    return;
  }
  struct udphdr *udp = (struct udphdr *) (((u_char *) ip) + ip->ip_hl * 4);
  struct riphdr *rip = (struct riphdr *) (((u_char *) udp) + sizeof(struct udphdr));
  struct rip_entry *rip_entry = (struct rip_entry *) (((u_char *) rip) + sizeof(struct riphdr));
  u_int riplen = ntohs(udp->uh_ulen) - sizeof(struct udphdr);
  u_int entries = (riplen - sizeof(struct riphdr)) / sizeof(struct rip_entry);
  char time[30];
  strftime(time, 30, "%F %T", timeinfo);

  //Header: version, command, number of entries, (domain), source addr, time received
  printf("[%s] RIPv%d %s with %d items", time, rip->rip_ver, rip_cmd(rip->rip_cmd), entries);
  if (rip->rip_ver == 2) {
    printf(", domain %-4d", rip->rip_domain);
  }
  printf("\nSrc IP: %s  src port: %d  dest port: %d\n",
         inet_ntoa(ip->ip_src), ntohs(udp->uh_sport), ntohs(udp->uh_dport));

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

void print_ripng_packet(struct tm *timeinfo, struct ip6_hdr *ip6) {
  if (ip6->ip6_nxt != IPPROTO_UDP) {
    //Ignoring IPv6 extensions
    return;
  }
  struct udphdr *udp = (struct udphdr *) (((u_char *) ip6) + sizeof(struct ip6_hdr));
  struct rip6hdr *rip6 = (struct rip6hdr *) (((u_char *) udp) + sizeof(struct udphdr));
  struct rip6_entry *rip6_entry = (struct rip6_entry *) (((u_char *) rip6) + sizeof(struct rip6hdr));
  u_int riplen = ntohs(udp->uh_ulen) - sizeof(struct udphdr);
  u_int entries = (riplen - sizeof(struct rip6hdr)) / sizeof(struct rip6_entry);
  char addr[INET6_ADDRSTRLEN], time[30];
  strftime(time, 30, "%F %T", timeinfo);

  //Header: version, command, number of entries, source addr, time received
  printf("[%s] RIPng %-8s with %d items\n", time, rip_cmd(rip6->rip6_cmd), entries);
  printf("Src IP: %s  src port: %d  dest port: %d\n",
         inet_ntop(AF_INET6, &ip6->ip6_src, addr, INET6_ADDRSTRLEN),
         ntohs(udp->uh_sport), ntohs(udp->uh_dport));

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
    print_rip_packet(localtime((time_t *) &header->ts.tv_sec),
                     (struct ip *) (packet + sizeof(struct ether_header)));
    break;

  case ETHERTYPE_IPV6:
    print_ripng_packet(localtime((time_t *) &header->ts.tv_sec),
                       (struct ip6_hdr *) (packet + sizeof(struct ether_header)));
    break;
  }
}

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

  fprintf(stderr, "Listening...\n");
  if (pcap_loop(handle, -1, sniff_handler, NULL) == -1)
    ERR("pcap_loop: %s\n", pcap_geterr(handle));

  pcap_close(handle);
  return 0;
}

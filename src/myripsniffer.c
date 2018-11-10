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
  printf("%8s, tag %-5u", rip_hops(ntohl(e->body.rip_metric)), ntohs(e->rip_tag));
  printf(" %s/%s -> ", inet_ntoa(e->body.rip_dest), inet_ntoa(e->body.rip_mask));
  if (e->body.rip_next_hop.s_addr == 0) {
    printf("originator");
  } else {
    printf("%s", inet_ntoa(e->body.rip_next_hop));
  }
  if (ntohs(e->rip_family) != AF_INET) {
    printf(" (family %d)", ntohs(e->rip_family));
  }
  printf("\n");
}

void print_ripng_entry(struct rip6_entry *e) {
  char addr[INET6_ADDRSTRLEN];
  if (e->rip6_metric == RIPNG_NEXT_HOP) {
    printf("Next hop for the following entries: %s\n",
           inet_ntop(AF_INET6, &e->rip6_dest, addr, INET6_ADDRSTRLEN));
    return;
  }
  printf("%8s, tag %-5u", rip_hops(e->rip6_metric), ntohs(e->rip6_tag));
  printf(" %s/%d\n", inet_ntop(AF_INET6, &e->rip6_dest, addr, INET6_ADDRSTRLEN),
         e->rip6_prefix);
}

void print_rip_packet(size_t riplen, struct riphdr *rip) {
  struct rip_entry *rip_entry = (struct rip_entry *) (((u_char *) rip) + sizeof(struct riphdr));
  u_int entries = (riplen - sizeof(struct riphdr)) / sizeof(struct rip_entry);

  //RIPng header
  printf("RIPv%d %s with %d items", rip->rip_ver, rip_cmd(rip->rip_cmd), entries);
  if (rip->rip_ver == 2) {
    printf(", domain %-4d", rip->rip_domain);
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

  //And kicking off the sniffer
  fprintf(stderr, "Listening...\n");
  if (pcap_loop(handle, -1, sniff_handler, NULL) == -1)
    ERR("pcap_loop: %s\n", pcap_geterr(handle));

  pcap_close(handle);
  return 0;
}

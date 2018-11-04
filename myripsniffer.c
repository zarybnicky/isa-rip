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


#define RIP_FILTER "portrange 520-521 and udp"
#define	RIP6_DEST "ff02::9"

void usage(char *argv[]) {
  fprintf(stderr, "Usage: %s -i INTERFACE\n", argv[0]);
}

struct rip_entry {
  u_short rip_family;
  u_short rip_tag;
  u_int32_t rip_dest;
  u_int32_t rip_dest_mask;
  u_int32_t rip_router;
  u_int32_t rip_metric;
};
struct rip {
  u_char rip_cmd;
  u_char rip_vers;
  u_short rip_zeros;
};
#define RIPCMD_REQUEST 1
#define RIPCMD_RESPONSE 2
#define RIPCMD_TRACEON 3
#define RIPCMD_TRACEOFF 4
#define RIPCMD_POLL 5
#define RIPCMD_POLLENTRY 6

struct rip6_entry {
  struct in6_addr rip6_dest;
  u_short rip6_tag;
  u_char rip6_plen;
  u_char rip6_metric;
};
struct rip6 {
  u_char rip6_cmd;
  u_char rip6_vers;
  u_char rip6_res1[2];
  struct rip6_entry rip6_nets[1];
};

char *rip_cmd(u_char cmd) {
  switch (cmd) {
  case RIPCMD_REQUEST:
    return "Request   ";
  case RIPCMD_RESPONSE:
    return "Response  ";
  case RIPCMD_TRACEON:
    return "Traceon   ";
  case RIPCMD_TRACEOFF:
    return "Traceoff  ";
  case RIPCMD_POLL:
    return "Poll      ";
  case RIPCMD_POLLENTRY:
    return "Poll Entry";
  default:
    return "(unknown) ";
  }
}

void sniff_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  (void) args;
  const struct ether_header *eptr = (struct ether_header *) packet;
  const struct ip *ip;
  const struct ip6_hdr *ip6;
  const struct udphdr *udp;
  char addr[INET6_ADDRSTRLEN];
  int rip_len;
  const struct rip *rip;
  const struct rip6 *rip6;

  switch (ntohs(eptr->ether_type)) {
  case ETHERTYPE_IP:
    ip = (struct ip*) (packet + sizeof(struct ether_header));
    if (ip->ip_p != IPPROTO_UDP) {
      return;
    }
    udp = (struct udphdr *) (packet + sizeof(struct ether_header) + ip->ip_hl * 4);
    rip = (struct rip *) (packet + sizeof(struct ether_header) + ip->ip_hl * 4 + sizeof(struct udphdr));
    rip_len = ntohs(udp->uh_ulen) - sizeof(struct udphdr);

    //Aligned to 70 chars
    printf("RIP %s                               %s",
           rip_cmd(rip->rip_cmd), ctime((const time_t*) &header->ts.tv_sec));
    printf("Src addr = %s, Src port = %d\n", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport));
    printf("payload length %d\n", rip_len);

    break;

  case ETHERTYPE_IPV6:
    ip6 = (struct ip6_hdr*) (packet + sizeof(struct ether_header));
    if (ip6->ip6_nxt != IPPROTO_UDP) {
      //Disregarding IPv6 extensions
      return;
    }
    udp = (struct udphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    rip6 = (struct rip6 *) (packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr));
    rip_len = ntohs(udp->uh_ulen) - sizeof(struct udphdr);

    //Aligned to 70 chars
    printf("RIPng %s                             %s",
           rip_cmd(rip6->rip6_cmd), ctime((const time_t*) &header->ts.tv_sec));
    printf("Src addr = %s, ", inet_ntop(AF_INET6, &ip6->ip6_src, addr, INET6_ADDRSTRLEN));
    printf("Src port = %d\n", ntohs(udp->uh_sport));
    printf("payload length %d\n", rip_len);
    break;
  }
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
      if (optopt == 'i') {
        fprintf(stderr, "Missing argument for option `-%c'\n", optopt);
      } else {
        fprintf(stderr, "Unknown option `-%c'\n", optopt);
      }
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

  if (pcap_loop(handle, -1, sniff_handler, NULL) == -1) {
    fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  pcap_close(handle);
  return 0;
}

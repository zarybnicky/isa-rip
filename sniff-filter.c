/*
 * sniff.c: live sniffing of packets with a simple  L2 analysis and filtering
 *
 * Usage: ./sniff-filter <pcap filter>, e.g. sniff "port 80"
 *
 * Advanced rights (bpf group) required to run the application
 *
 * (c) Petr Matousek, 2015
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <err.h>

#include <netinet/ether.h>
#include <time.h>

#ifndef PCAP_ERRBUF_SIZE
#define PCAP_ERRBUF_SIZE (256)
#endif

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol

int n = 0;

// mypcap_handler() is a function that processes captured packets
// the function is called by pcap_loop()
void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ip *my_ip;               // pointer to the beginning of IP header
  struct ether_header *eptr;      // pointer to the beginning of Ethernet header
  const struct tcphdr *my_tcp;    // pointer to the beginning of TCP header
  const struct udphdr *my_udp;    // pointer to the beginning of UDP header
  u_int size_ip;

  n++;
  // print the packet header data
  printf("Packet no. %d:\n",n);
  printf("\tLength %d, received at %s",header->len,ctime((const time_t*)&header->ts.tv_sec));
  //    printf("Ethernet address length is %d\n",ETHER_HDR_LEN);

  // read the Ethernet header
  eptr = (struct ether_header *) packet;
  printf("\tSource MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_shost)) ;
  printf("\tDestination MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_dhost)) ;

  // see /usr/include/net/ethernet.h for types
  switch (ntohs(eptr->ether_type)) {
  case ETHERTYPE_IP: // IPv4 packet
    printf("\tEthernet type is  0x%x, i.e. IP packet \n", ntohs(eptr->ether_type));
    my_ip = (struct ip*) (packet+SIZE_ETHERNET);        // skip Ethernet header
    size_ip = my_ip->ip_hl*4;                           // length of IP header

    printf("\tIP: id 0x%x, hlen %d bytes, version %d, total length %d bytes, TTL %d\n",ntohs(my_ip->ip_id),size_ip,my_ip->ip_v,ntohs(my_ip->ip_len),my_ip->ip_ttl);
    printf("\tIP src = %s, ",inet_ntoa(my_ip->ip_src));
    printf("IP dst = %s",inet_ntoa(my_ip->ip_dst));

    switch (my_ip->ip_p){
    case 2: // IGMP protocol
      printf(", protocol IGMP (%d)\n",my_ip->ip_p);
      break;
    case 6: // TCP protocol
      printf(", protocol TCP (%d)\n",my_ip->ip_p);
      my_tcp = (struct tcphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the TCP header
      printf("\tSrc port = %d, dst port = %d, seq = %u",ntohs(my_tcp->th_sport), ntohs(my_tcp->th_dport), ntohl(my_tcp->th_seq));
      if (my_tcp->th_flags & TH_SYN)
	printf(", SYN");
      if (my_tcp->th_flags & TH_FIN)
	printf(", FIN");
      if (my_tcp->th_flags & TH_RST)
	printf(", RST");
      if (my_tcp->th_flags & TH_PUSH)
	printf(", PUSH");
      if (my_tcp->th_flags & TH_ACK)
	printf(", ACK");
      printf("\n");
      break;
    case 17: // UDP protocol
      printf(", protocol UDP (%d)\n",my_ip->ip_p);
      my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the UDP header
      printf("\tSrc port = %d, dst port = %d, length %d\n",ntohs(my_udp->uh_sport), ntohs(my_udp->uh_dport), ntohs(my_udp->uh_ulen));
      break;
    default:
      printf(", protocol %d\n",my_ip->ip_p);
    }
    break;

  case ETHERTYPE_IPV6:  // IPv6
    printf("\tEthernet type is 0x%x, i.e., IPv6 packet\n", ntohs(eptr->ether_type));
    break;
  case ETHERTYPE_ARP:  // ARP
    printf("\tEthernet type is 0x%x, i.e., ARP packet\n", ntohs(eptr->ether_type));
    break;
  default:
    printf("\tEthernet type 0x%x, not IPv4\n", ntohs(eptr->ether_type));
  }
}

int main(int argc, char *argv[]) {
  char errbuf[PCAP_ERRBUF_SIZE];  // constant defined in pcap.h
  pcap_t *handle;                 // packet capture handle
  char *dev;                      // input device
  struct in_addr a,b;
  bpf_u_int32 netaddr;            // network address configured at the input device
  bpf_u_int32 mask;               // network mask of the input device
  struct bpf_program fp;          // the compiled filter

  if (argc != 2)
    errx(1, "Usage: %s <pcap filter>", argv[0]);

  // open the device to sniff data
  if ((dev = pcap_lookupdev(errbuf)) == NULL)
    err(1, "Can't open input device");

  // get IP address and mask of the sniffing interface
  if (pcap_lookupnet(dev, &netaddr, &mask, errbuf) == -1)
    err(1, "pcap_lookupnet() failed");

  a.s_addr=netaddr;
  printf("Opening interface \"%s\" with net address %s,", dev, inet_ntoa(a));
  b.s_addr=mask;
  printf("mask %s for listening...\n", inet_ntoa(b));

  // open the interface for live sniffing
  if ((handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL)
    err(1,"pcap_open_live() failed");

  // compile the filter
  if (pcap_compile(handle, &fp, argv[1], 0, netaddr) == -1)
    err(1,"pcap_compile() failed");

  // set the filter to the packet capture handle
  if (pcap_setfilter(handle, &fp) == -1)
    err(1,"pcap_setfilter() failed");

  // read packets from the interface in the infinite loop (count == -1)
  // incoming packets are processed by function mypcap_handler()
  if (pcap_loop(handle, -1, mypcap_handler, NULL) == -1)
    err(1, "pcap_loop() failed");

  // close the capture device and deallocate resources
  pcap_close(handle);
  return 0;
}

/**
 * ISA18: Tools for monitoring and sniffing RIP messages
 * FIT VUT Brno
 * Author: xzaryb00 - Jakub Zarybnický (xzaryb00)
 *
 * Sniffer for RIP/RIPng using libpcap
 */

#ifndef ISA_MYRIPSNIFFER_H
#define ISA_MYRIPSNIFFER_H

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

int main (int argc, char *argv[]);
void sniff_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_rip_packet(size_t riplen, struct riphdr *rip);
void print_ripng_packet(size_t riplen, struct rip6hdr *rip6);
void print_ripng_entry(struct rip6_entry *e);
void print_ripv1_entry(struct rip_entry *e);
void print_ripv2_entry(struct rip_entry *e);

#endif /* ISA_MYRIPSNIFFER_H */

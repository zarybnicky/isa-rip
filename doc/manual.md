---
title: Tools for sniffing and generating messages of simple distance-vector protocols
author: Jakub Zárybnický
date: November 2018
documentclass: report
---

# Introduction to RIP
## RIPv1
@pizza2000identification

## RIPv2
## RIPng

# RIP Sniffer
## Design
## Usage
To use the sniffer, simply find the name of the interface you want to listen on,
and call:

    ./myripsniffer -i INTERFACE

The sniffer will print a human-readable version of the caught packets on
`stdout`. Any errors will be printed out to `stderr` and the sniffer will exit
with a non-zero error code.

# RIPng Response
## Design
## Usage
To use the RIPng response crafter, you'll need the name of your network
interface and details about the network you want to advertise.

    ./myripresponse -i IFACE -r NET/MASK [-n NEXT-HOP] [-m METRIC] [-t TAG]

The available options are:
* `-i IFACE`: mandatory, the name of the interface to send the crafted packet to
* `-r NET/MASK`: mandatory, address and mask of the advertised network,
  e.g. `-r 2001:db8:0:abcd::/64`
* `-n NEXT-HOP`: optional, address of the next hop for the advertised network,
  will be `::` if not provided
* `-m METRIC`: optional, the RIP metric, will be 1 if not provided
* `-t TAG`: optional, router tag, will be 0 if not provided

# RIPng Request
## Design
## Usage

# Literature

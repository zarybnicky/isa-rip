---
title: Nástroje monitorující a generující zprávy jednoduchých distance-vector protokolů
author: Jakub Zárybnický
date: Listopad 2018
documentclass: report
---

# Úvod do RIP
## RIPv1
@rfc1058 @rfc1388 @rfc2082 @rfc2453 @rfc4822 @rfc2080 @getaddrinfo @beej @tcpdump

## RIPv2
## RIPng

# Odposlouchávání RIP
## Návrh
## Použití
Pro odposlouchávání RIP zpráv stačí zjistit jméno rozhraní, na kterém chcete
poslouchat:

    ./myripsniffer -i INTERFACE

Program pak bude na stdout vypisovat obsah zachycených RIP zpráv. Jakékoliv
chyby budou vypisovány na stderr a program v případě chyby skončí s nenulovým
kódem.

## Odposlechnuté zprávy


# Podvržení RIPng odpovědi
## Návrh
## Použití
Pro odeslání RIPng odpovědi je potřeba jméno rozhraní, na kterém chcete
poslouchat, a detaily podvrhované cesty (adresa a maska, volitelně pak 'next
hop', metrika a tag):

    ./myripresponse -i IFACE -r NET/MASK [-n NEXT-HOP] [-m METRIC] [-t TAG]

Možnosti programu jsou následující:
* `-i IFACE`: povinné, rozhraní, které se má použít pro odeslání paketu
* `-r NET/MASK`: povinné, adresa a maska podvrhované sítě (např. `-r 2001:db8:0:abcd::/64`)
* `-n NEXT-HOP`: volitelné, adresa 'next hop' podvrhované sítě
* `-m METRIC`: volitelné, RIP metrika sítě, výchozí je 1
* `-t TAG`: volitelné, tag sítě, výchozí je 0

## Útok na RIPng router

# Podvržení RIPng dotazu
## Návrh
## Použití


# Literatura

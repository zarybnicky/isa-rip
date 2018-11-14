---
title: Nástroje monitorující a generující zprávy jednoduchých distance-vector protokolů
author: Jakub Zárybnický
date: Listopad 2018
documentclass: report
---

# Úvod do RIP
Routing Information Protocol (RIP) je směrovací protokol založený na vektorech
vzdálenosti (distance-vector routing protocol), který umožňuje routerům
vyměňovat si informace o topologii sítě. Je to jeden z nejstarších směrovacích
protokolů, který se využíval již na původním ARPANETu.

Vzdálenost se měří v počtu skoků k cíli (hop count) a je omezena na 15 (16
reprezentuje nedosažitelnou síť), což omezuje velikost sítí, kde může být RIP
používán. Routery pro určení nejlepší cesty využívají Bellman-Fordův algoritmus.

Každý router co 30 vteřin odesílá zprávy se stavem své směrovací tabulky, a to
pomocí protokolu UDP na portu 520 (RIPng na portu 521).

Existují tři varianty protokolu RIP, dvě pro IPv4 - RIPv1 a RIPv2 a jedna s
podporou IPv6 - RIPng.

## RIPv1
RIPv1 [@rfc1058] je nejjednodušší verze protokolu, kdy je informace o síti
komunikována pouze její adresou a počtem skoků k ní. Protokol je tedy založen na
třídách IPv4 adres, nelze specifikovat masku sítě. Hromadné zprávy jsou
rozesílány broadcastem, všechna komunikace probíhá na portu 520.

## RIPv2
RIPv2 je rozšíření protokolu RIPv1 s podporou beztřídních IPv4 adres, podporou
tagů sítí a také s podporou autentizace. Mimo RFC definujícího RIPv2 [@rfc1388]
také vyšlo několik jeho rozšíření [@rfc2082; mj. @rfc2453; @rfc4822], které
definují další druhy autentizace zpráv -- pomocí MD5 nebo SHA hašů. Komunikace
probíhá na portu 520, hromadné zprávy jsou rozesílány multicastem na adresu
224.0.0.9.

## RIPng
RIPng [@rfc2080] je další varianta protokolu RIP, která přidává podporu
IPv6. RIPng na rozdíl od RIPv2 nepodporuje autentizaci zpráv, kterou měl
nahradit IPsec. Komunikace probíhá na portu 521, hromadné zprávy jsou rozesílány
na adresu ff02::9.

# Odposlouchávání RIP
## Návrh
@tcpdump

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
@getaddrinfo @beej

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

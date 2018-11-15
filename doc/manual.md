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
První praktická část projektu je implementace nástroje pro odposlouchávání RIP
packetů pomocí knihovny pcap [@tcpdump] a vypsání jejich obsahu.

Knihovna pcap je relativně dobře zdokumentovaná, takže nastavení odposlouchávání
samotného je relativně přímočaré. Pro vypsání obsahu paketů je potřeba vyčíst
si z relevantních RFC strukturu RIP, definovat ji jako `struct` jazyka C a najít
si struktury hlaviček Ethernetu, IPv4/IPv6 a UDP v systémových hlavičkových
souborech. Vypsat obsah paketů už pak znamená jen následovat struktury a ve
vhodných chvílích převést hodnoty ze síťového pořadí bytů na místní.

V knihovně pcap používám pro omezení množství zachycených dat filtr, konkrétně
filtr `portrange 520-521 and udp`, který sice nevyloučí pakety, které nejsou RIP
pakety, ale výrazně jejich množství sníží.

Pro zjednodušení kódu jsem se rozhodl psát program jako jednoúčelový a vypisovat
získaná data přímo na stdout, bez jakéhokoli dočasného bufferu (což by v C
znamenalo neustálé žonglování `malloc`u, `sprintf` a `strcat`) nebo možnosti
zvolit popisovač, do kterého zapisovat.

Struktura kódu samotného je pak snad naprosto jednoznačná:

* `sniff_handler`, který se zbaví všech vrstev před RIP (tj. Ethernet, IP a UDP)
  a vypíše řádek s časem, zdrojovým IP a zdrojovým i cílovým portem,

      [2018-11-15 17:46:03] from 10.0.0.1 at port 520 to port 520
* `print_rip_packet`/`print_ripng_packet`, které vypíšou obsah hlavičky RIP, tj.
  verzi, příkaz a počet položek, v případě RIPv2 i doménu,

      RIPng Response with 5 items
* sadu funkcí `print_rip*_entry`, které vypisují obsah jednotlivých položek RIP
  paketu,

      1 hops, tag 0     fd00::/64
* definice hlaviček a položek RIP v `rip.h`, jelikož jsou sdílené i s dalšími
  programy.

## Použití
Pro odposlouchávání RIP zpráv stačí zadat jméno rozhraní, na kterém chcete
poslouchat. Program také vyžaduje oprávnění roota, je potřeba jej spouštět se
`sudo` nebo jako root.

    ./myripsniffer -i INTERFACE

Program pak bude na stdout vypisovat obsah zachycených RIP zpráv. Jakékoliv
chyby budou vypisovány na stderr a program v případě chyby skončí s nenulovým
kódem.

## Odposlechnuté zprávy
Součástí zadání bylo zachytit zprávy RIP Response odesílané směrovačem na
poskytnutém virtuálním stroji. Z důvodu chyby v poskytnutém skriptu `genconf.py`
používám login `xxaryb00` a ne můj login `xzaryb00`.

V zájmu stručnosti uvádím pouze jednu kopii každého zachyceného paketu - sniffer
i Wireshark zachycují kopie dvě. Zachycené cesty i heslo použité pro zabezpečení
jsou snad z níže uvedeného přepisu zřejmé.

    $ sudo ./myripsniffer -i vboxnet0
    Listening...
    [2018-11-15 18:06:16] from fe80::a00:27ff:fe07:dd12 at port 521 to port 521
    RIPng Response with 5 items
      1 hops, tag 0     fd00::/64
      1 hops, tag 0     fd00:0:78::/64
      1 hops, tag 0     fd00:d4:2df0::/64
      1 hops, tag 0     fd00:10a:38b8::/64
      1 hops, tag 0     fd00:900:1230::/64

    [2018-11-15 18:06:23] from 10.0.0.1 at port 520 to port 520
    RIPv2 Response with 5 items, domain 0
    Auth type: password   Password: ISA>29c12308c94
      1 hops, tag 0     10.48.48.0/255.255.255.0
      1 hops, tag 0     10.97.121.0/255.255.255.0
      1 hops, tag 0     10.114.234.0/255.255.255.0
      1 hops, tag 0     10.218.98.0/255.255.255.0

    [2018-11-15 18:06:23] from 192.168.56.101 at port 520 to port 520
    RIPv2 Response with 6 items, domain 0
    Auth type: password   Password: ISA>29c12308c94
      1 hops, tag 0     10.0.0.0/255.255.255.0
      1 hops, tag 0     10.48.48.0/255.255.255.0
      1 hops, tag 0     10.97.121.0/255.255.255.0
      1 hops, tag 0     10.114.234.0/255.255.255.0
      1 hops, tag 0     10.218.98.0/255.255.255.0

# Podvržení RIPng odpovědi
## Návrh
Druhou částí zadání je vytvoření nástroje pro podvrhnutí zprávy RIP Response
protokolu RIPng. Při implementaci jsme omezení na používání knihoven dostupných
na typické instalaci Linuxového systému, tj. BSD/POSIX sokety.

Struktura programu je relativně jednoduchá -- připravit si obsah zprávy na
základě zadaných parametrů, nejprve v relevantních strukturách a nakonec v
bufferu připraveného pro odeslání, nachystat si soket takový, který může
odesílat UDP data z portu 521 multicastem na adresu `ff02::9` na port 521,
nastavit IPv6 možnosti multicastu (počet skoků, rozhraní), a nakonec zavolat
`sendto`. (Zkoušel jsem i `sendmsg`, ale pro takové jednoduché použití je
výsledný kód skoro stejné dlouhý a `sendmsg` kód je trochu hůř čitelný.)

Pro vytvoření RIP zprávy používám struktury vytvořené v minulém úkolu. Zpráva má
tři části, hlavičku, položku next hop a položku se záznamem o síti. Položku next
hop není nutné uvádět v případě, že je rovna `::`, jelikož to je výchozí hodnota
next hopu.

Jako reference k BSD/POSIX soketům mi sloužila dnes již klasická příručka
[@beej], která mj. doporučuje použití `getaddrinfo` [@getaddrinfo] - dle diskuzí
se spolužáky docela neobvyklé řešení. `getaddrinfo` se postará o zvolení správné
adresy i portu, na nás zbude nastavení správných možností pro multicast
(konkrétně `IPV6_MULTICAST_IF` a `IPV6_MULTICASE_HOPS`).

Abychom mohli data odesílat z 'privilegovaného portu' 521, je potřeba program
spouštět s oprávněními roota (nebo se správně nastavenými 'capabilities' pomocí
`setcap`).

## Použití
Pro odeslání RIPng odpovědi je potřeba jméno rozhraní, na kterém chcete
poslouchat, a detaily podvrhované cesty (adresa a maska, volitelně pak 'next
hop', metrika a tag). Program také potřebuje oprávnění roota, je tedy potřeba
jej spouštět se `sudo` nebo jako root.

    ./myripresponse -i IFACE -r NET/MASK [-n NEXT-HOP] [-m METRIC] [-t TAG]

Možnosti programu jsou následující:

* `-i IFACE`: povinné, rozhraní, které se má použít pro odeslání paketu
* `-r NET/MASK`: povinné, adresa a maska podvrhované sítě (např. `-r 2001:db8:0:abcd::/64`)
* `-n NEXT-HOP`: volitelné, adresa 'next hop' podvrhované sítě
* `-m METRIC`: volitelné, RIP metrika sítě, výchozí je 1
* `-t TAG`: volitelné, tag sítě, výchozí je 0

## Útok na RIPng router
Součástí zadání je i 'útok na směrovač RIP', tedy odeslání zprávy RIP Response a
zjištění její účinku na směrovací tabulku virtuálního routeru. Útok demonstruji
třemi přepisy z terminálu, první je výstup příkazu pro odeslání RIP Response:

    $ sudo ./myripresponse -i vboxnet0 -r 2001:db8:0:abcd::/64
    Binding to port 521 at ff02::9%vboxnet0
    Sending message... OK


Vzhled odeslané zprávy ve snifferu z předchozího kroku:

    $ sudo ./myripsniffer -i vboxnet0
    Listening...
    [2018-11-15 18:56:48] from fe80::800:27ff:fe00:0 at port 521 to port 521
    RIPng Response with 1 items
      1 hops, tag 0     2001:db8:0:abcd::/64


A jako poslední přepis směrovací tabulky z virtuálního stroje se směrovačem:

    Hello, this is Quagga (version 0.99.16).
    Copyright 1996-2005 Kunihiro Ishiguro, et al.

    User Access Verification

    Password:
    Routing> show ipv6 route
    Codes: K - kernel route, C - connected, S - static, R - RIPng, O - OSPFv3,
           I - ISIS, B - BGP, * - FIB route
    
    K>* ::/96 via ::1, lo0, rej
    C>* ::1/128 is directly connected, lo0
    K>* ::fff:0.0.0.0/96 via ::1, lo, rej
    R>* 2001:db8:0:abcd::/64 [120/2] via fe80::800:27ff:fe00:0, em0, 00:02:55
    C>* fd00::/64 is directly connected, em0
    C>* fd00:0:78::/64 is directly connected, lo0
    C>* fd00:d4:2df0::/64 is directly connected, lo0
    C>* fd00:10a:38b8::/64 is directly connected, lo0
    C>* fd00:900:1230::64 is directly connected, lo0
    K>* fe80::/10 via ::1, lo, rej
    C * fe80::/64 is directly connected, lo0
    C>* fe80::/64 is directly connected, em0
    K>* ff02::/19 via ::1, lo, rej


# Podvržení RIPng dotazu
## Návrh
## Použití


# Literatura

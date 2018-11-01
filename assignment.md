# Společná část popisu:
Vytvořte komunikující aplikaci podle konkrétní vybrané specifikace pomocí síťové
knihovny BSD sockets (pokud není ve variantě zadání uvedeno jinak). Projekt bude
vypracován v jazyce C/C++. Pokud individuální zadání nespecifikuje vlastní
referenční systém, musí být projekt přeložitelný a spustitelný na serveru
merlin.fit.vutbr.cz pod operačním systémem Linux.

Vypracovaný projekt uložený v archívu .tar a se jménem xlogin00.tar odevzdejte
elektronicky přes IS. Soubor nekomprimujte.

* Termín odevzdání je 19.11.2018 (hard deadline). Odevzdání e-mailem po uplynutí
  termínu, dodatečné opravy či doplnění kódu není možné.
* Odevzdaný projekt musí obsahovat:
* soubor se zdrojovým kódem (dodržujte jména souborů uvedená v konkrétním
  zadání),
* funkční Makefile pro překlad zdrojového souboru,
* dokumentaci (soubor manual.pdf), která bude obsahovat uvedení do problematiky,
  návrhu aplikace, popis implementace, základní informace o programu, návod na
  použití. V dokumentaci se očekává následující: titulní strana, obsah, logické
  strukturování textu, přehled nastudovaných informací z literatury, popis
  zajímavějších pasáží implementace, použití vytvořených programů a literatura.
* soubor README obsahující krátký textový popis programu s případnými
  rozšířeními/omezeními, příklad spuštění a seznam odevzdaných souborů,
* další požadované soubory podle konkrétního typu zadání.
* Pokud v projektu nestihnete implementovat všechny požadované vlastnosti, je
  nutné veškerá omezení jasně uvést v dokumentaci a v souboru README.
* Co není v zadání jednoznačně uvedeno, můžete implementovat podle svého
  vlastního výběru. Zvolené řešení popište v dokumentaci.
* Při řešení projektu respektujte zvyklosti zavedené v OS unixového typu (jako
  je například formát textového souboru).
* Vytvořené programy by měly být použitelné a smysluplné, řádně komentované a
  formátované a členěné do funkcí a modulů. Program by měl obsahovat nápovědu
  informující uživatele o činnosti programu a jeho parametrech. Případné chyby
  budou intuitivně popisovány uživateli.
* Aplikace nesmí v žádném případě skončit s chybou SEGMENTATION FAULT ani jiným
  násilným systémovým ukončením (např. dělení nulou).
* Pokud přejímáte krátké pasáže zdrojových kódů z různých tutoriálů či příkladů
  z Internetu (ne mezi sebou), tak je nutné vyznačit tyto sekce a jejich autory
  dle licenčních podmínek, kterými se distribuce daných zdrojových kódů řídí. V
  případě nedodržení bude na projekt nahlíženo jako na plagiát.
* Konzultace k projektu podává vyučující, který zadání vypsal.
* Před odevzdáním zkontrolujte, zda jste dodrželi všechna jména souborů
  požadovaná ve společné části zadání i v zadání pro konkrétní
  projekt. Zkontrolujte, zda je projekt přeložitelný.

## Hodnocení projektu:
* Maximální počet bodů za projekt je 20 bodů.
* Maximálně 15 bodů za plně funkční aplikace.
* Maximálně 5 bodů za dokumentaci. Dokumentace se hodnotí pouze v případě
  funkčního kódu. Pokud kód není odevzdán nebo nefunguje podle zadání,
  dokumentace se nehodnotí.

* Příklad kriterií pro hodnocení projektů:
* nepřehledný, nekomentovaný zdrojový text: až -7 bodů
* nefunkční či chybějící Makefile: až -4 body
* nekvalitní či chybějící dokumentace: až -5 bodů
* nedodržení formátu vstupu/výstupu či konfigurace: -10 body
* odevzdaný soubor nelze přeložit, spustit a odzkoušet: 0 bodů
* odevzdáno po termínu: 0 bodů
* nedodržení zadání: 0 bodů
* nefunkční kód: 0 bodů
* opsáno: 0 bodů (pro všechny, kdo mají stejný kód), návrh na zahájení
  disciplinárního řízení.

# Popis varianty:
## ZADÁNÍ:
Vašim úkolem je:
1. nastudovat si směrovací protokoly RIP a RIPng;
2. naprogramovat sniffer RIPv1, RIPv2 a RIPng zpráv;
3. naprogramovat podvrhávač falešných RIPng Response zpráv;
4. za použití obou nástrojů, které jste si předpřipravili v předchozím bodě pak
   provést úspěšný útok;
5. Bonus: naprogramovat podvrhávač falešných RIPng Request zpráv.

## TESTOVÁNÍ:
Pro případné testování a plnění bodu 4) zadání je pro Vás připraven image
virtuálního FreeBSD počítače, který je spustitelný např. pomocí aplikace VMWare
Player nebo VirtualBox. Na tomto virtuálním počítači pak běží SW směrovač Quagga
s rozchozenými instancemi RIPv2, RIPng a ND Router Advertisment. Tento router
pak šíří směrovací informace na své rozhraní em0 (s fixní IPv4 adresou).

Po nastartování virtuálního počítače se přihlašte pomocí loginu student s heslem
student. Ve svém domovském adresáři pak spusťte příkaz:

`sudo /usr/sbin/genconf.py <xlogin00>`, kde jediným vstupním parametrem je váš
VUT-FIT login, který vám vygeneruje pro Vás jedinečnou konfiguraci a restartuje
démona Quaggy. POZOR, testovací image je pro Vás přirpaven jen pro potřeby
generování relevantního provozu a provázání unikátního zadání s Vašim loginem, v
žádném případě se na něm (v něm) nepokoušejte projekt implementovat!!!

## UPŘESNĚNÍ ZADÁNÍ:

### Ad 1)
V dobré dokumentaci se OČEKÁVÁ následující: titulní strana, obsah, logické
strukturování textu, výcuc relevantních informací z nastudované literatury,
popis zajímavějších pasáží implementace, sekce o testování, bibliografie, popisy
k řešení bonusových zadání.

### Ad 2)
V rámci implementace je dovoleno použít knihovny libpcap a všech jejich
vymožeností. očekáva se použití promiskuitního módu síťové karty a prezentace
odchycených paketů pro uživatele nějakou smysluplnou formou.

Závazný formát výstupní binárky: `./myripsniffer -i <rozhraní>`, kde význam
parametru je následující:

* -i: <rozhraní> udává rozhraní, na kterém má být odchyt paketů prováděn.

### Ad 3)
V rámci implementace je ZAKÁZÁNO použít jekékoli nestandardní knihovny a
knihovních funkcí pro kraftování RIP zpráv, držte se jen čistě BSD soketů! Lze
použít knihovny netdb.h, sniff.c (z příkladů), inet.h a
ifaddrs.h. Implementovaný podvrhávač používá strukturu zprávy RIPng.

Závazný formát výstupní binárky: `./myripresponse -i <rozhraní> -r
<IPv6>/[16-128] {-n <IPv6>} {-m [0-16]} {-t [0-65535]}`, kde význam parametrů je
následující:

* -i: <rozhraní> udává rozhraní, ze kterého má být útočný paket odeslán;
* -r: v <IPv6> je IP adresa podvrhávané sítě a za lomítkem číselná délka masky sítě;
* -n: <IPv6> za tímto parametrem je adresa next-hopu pro podvrhávanou routu, implicitně ::;
* -m: následující číslo udává RIP Metriku, tedy počet hopů, implicitně 1;
* -t: číslo udává hodnotu Router Tagu, implicitně 0.

### Ad 4)
Vašim cílem je odchytit RIP Response zprávy SW směrovače pomocí Vaší aplikace z
bodu 2). Do dokumentace pak povinně uveďte, které všechny routy se Vám podařilo
odchytit! Další inspekcí zpráv zjistěte autentizační heslo, kterým jsou zprávy
zabezpečeny. Pomocí aplikace z bodu 3) podvrhněte SW směrovači zprávou RIP
Response routu 2001:db8:0:abcd::/64. Úspěch podvrhnutí si můžete ověřit tím, že
se ve virtuálním počítači připojíte k routovacímu démonu pomocí příkazu telnet
127.0.0.1 2601, zadáte přístupové heslo do konzole c (písmenko malé cé) a v
shellu routovacího démona zadáte příkaz show ipv6 route, který Vám zobrazí
aktuální směrovací tabulku.

### Ad 5)
Vypracování je DOBROVOLNÉ a bonifikováno až +4 body, které však nepřesáhnou
maximální počet bodů z celého projektu! Lze jimi však záplatovat bodové ztráty z
předchozích povinných částí.

Závazný formát výstupní binárky: `./myriprequest`, a protože se jedná o bonus k
zadání, tak jakékoli další případné parametry jsou čistě ve Vaší režii, uveďte
však případné správné použití v souboru README.

## DOPORUČENÍ/OMEZENÍ:
* Všechny implementované programy by měly být použitelné a řádně
  komentované. Pokud už přejímáte zdrojové kódy z různých tutoriálů či příkladů
  z Internetu (ne mezi sebou pod hrozbou ortelu disciplinární komise), tak je
  POVINNÉ správně vyznačit tyto sekce a jejich autory dle licenčních podmínek,
  kterými se distribuce daných zdrojových kódů řídí. V případě nedodržení bude
  na projekt nahlíženo jako na plagiát!
* U syntaxe vstupních voleb jednotlivým programům složené závorky {} znamenají,
  že volba je nepovinná, (pokud není přítomna, tak se použíje implicitní
  hodnota), přičemž pořadí jednotlivých voleb a jejich parametrů může být
  libovolné. Pro jejich snadné parsování se doporučuje použít funkci getopt().
* Když je v sekci o testování napsáno, že virtuální router plive veškerou svou
  komunikaci na rozhraní em0, tak vhodně využijte propojení tohoto rozhraní s
  virtuálním síťovým adaptérem hostitelského (např. Host-only adapter) počítače
  s OS, na kterém samotný projekt implementujete!
* Výsledky vaší implementace by měly být co možná nejvíce multiplatformní mezi
  OS založenými na unixu, ovšem samotné přeložení projektu a funkčnost vaší
  aplikace budou testovány na referenčním Linux image pro předmět ISA, kterýžto
  bude sloužit jako virtuální mašinka s pravděpodobně jedním síťovým rozhraním.
* Pokud jste ještě nikdy nevirtualizovali, třeba vám pomůže následující článek
  http://www.brianlinkletter.com/how-to-use-virtualbox-to-emulate-a-network/
* V rámci testování ve vašich podmínkách zkuste:
* FreeBSD virtuální počítač <=== virtuální síťový adaptér ===> váš počítač
* V rámci reálného testování můžete očekávat zapojení:
* Vaše implementace v referenčním image <=== bridgovaný síťový adaptér ===> reálný RIPng router
* Pokud se Vám zdá testování Vašeho monitorovacího nástroje (bod 2 zadání) přes
  FreeBSD virtuálku těžkopádné, tak Vám nabízím alternativu v podobě nástroje
  tcpreplay, kterým máte možnost si na zvolené rozhraní nechat "přehrát" obsah
  PCAP souboru. Vhodným PCAP souborem tak může být takový, který si pořídíte ve
  Wireshark nahráním komunikace na virtuálním adaptéru, na kterém je FreeBSD
  virtuálka. Lenivější mohou použít tento PCAP soubor, který jsem výše uvedeným
  způsobem pořídil já nad mou lokální kopií FreeBSD image (jehož funkčnost jsem
  tímto pro potřeby ISA projektu znovuověřil).

# LITERATURA:
* RFC1058 - RIP version 1 (http://tools.ietf.org/html/rfc1058)
* RFC2453 - RIP version 2 (http://tools.ietf.org/html/rfc2453)
* RFC2080 - RIPng for IPv6 (http://tools.ietf.org/html/rfc2080)
* stránky knihovny libpcap (http://www.tcpdump.org/)

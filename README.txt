Popis programu isa-tazatel:

Whois tazatel je aplikácia, ktorá pozostáva z dvoch častí. Prvá časť získava DNS záznamy z vloženej IP adresy alebo hostname. Druhá časť získava WHOIS záznamy pre vloženú adresu a to zo serveru, ktorý opäť zadá uživateľ a to vo forme IP adresy alebo hostname.

Príklady spustenia: 

$ ./isa-tazatel -w whois.ripe.net -q www.fit.vutbr.cz
$ ./isa-tazatel -q 147.229.9.23 -w 193.0.6.135
$ ./isa-tazatel -q 2001:67c:1220:809::93e5:917 -w 193.0.6.135

Zoznam odovzdaných súborov:
1. isa-tazatel.c
2. Makefile
3. manual.pdf
4. README.txt

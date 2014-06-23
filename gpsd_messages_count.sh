#!/bin/sh
perl -pe 's/length \d+/length xxx/g; s/SiRF: DBG 0xff.*$/SiRF: DBG 0xff: xxxx/g; s/SiRF: DEV 0xe1.*$/SiRF: DEV 0xe1: xxxx/g; s,DATA: DOPS computed/reported.*$,DATA: DOPS computed/reported: xxx,g; s/PROG: SiRF: NTPD valid time MID 0x(\d+).*/PROG: SiRF: NTPD valid time MID $1/g;s/DATA: SiRF: MND 0x02: time.*$/DATA: SiRF: MND 0x02: time=xxx, lat,lon,alt/g; s/PROG: 50B: SF:(\d+).*$/PROG: 50B: SF:$1 xxxx/g' "$@" | 
sort | uniq -c | egrep '50B:|SiRF:|DOPS' 


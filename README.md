# tls-scanning-reporting

Middels dit script kan een scan van testssl.sh ingelezen worden en aan de hand van de classificatie zoals ingesteld in classifications.conf gerapporteerd worden naar een in te stellen HTML bestand:
```
./analyze.sh <output-testssl>.json <outputreport>.html
```


Het testssl.sh script (zie https://github.com/testssl/testssl.sh) kan op basis van een inputfile werken, die per te scannen IP:poort combinatie de volgende regel moet bevatten:
```
-n none -e -s -f -p -S -P -h <IP>:<poort>
```

De gebruikte opties zijn:
```
-n	if "none": do not try any DNS lookups, "min" queries A, AAAA and MX records
-e	checks each local cipher remotely
-s	tests standard cipher categories by strength
-f	checks forward secrecy settings
-p	checks TLS/SSL protocols, for HTTP: including QUIC/HTTP/3 and ALPN/HTTP2 (and SPDY)
-S	displays the server's default picks and certificate info
-P	displays the server's picks: protocol+cipher
-h	tests HSTS, HPKP, server/app banner, security headers, cookie, reverse proxy, IPv4 address
```

De inputfile kan gegenereerd worden met de hand, of bijvoorbeeld op basis van een nmap scan, waarbij te scannen poortnummers vooraf aangegeven kunnen worden:
```
nmap -n -v -p443,8443,9443 -P0 --open 10.20.78.0/24 -oG nmap-output
```

Deze nmap-output kan vervolgens direct in het testssl script geladen worden als input, waarbij de naam van de json output file opgegeven dient te worden::
```
./testssl.sh -n none -e -s -f -S -p -h --jsonfile <bestandsnaam>.json --mode parallel --file nmap-output
```
Of als er https actief is op een andere poort dan 443, kan het nmap bestand worden omgezet naar een gefixeerd IP:poort gebaseerde inputfile:
```
awk '/^Host:/&&/Ports:/{ip=$2;split($0,a,"Ports: ");split(a[2],p,",");for(i in p){gsub(/^ +| +$/,"",p[i]);split(p[i],f,"/");if(f[2]=="open"&&f[3]=="tcp")print "-n none -e -s -f -p -S -P -h " ip ":" f[1]}}' nmap-output > inputfile.txt
```

Testssl wordt als volgt aangeroepen met een inputfile, waarbij de naam van de json file opgegeven dient te worden:
```
./testssl.sh --jsonfile <bestandsnaam>.json --append --mode parallel --file inputfile.txt
```

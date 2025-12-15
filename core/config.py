# Liste von Ports, die wir als "Webserver" identifizieren
WEB_PORTS = ['80', '443', '8080', '8000', '8081', '3000', '5000', '8443']

# MAXIMALE GLEICHZEITIGE WEB SCANS (nur relevant, wenn mehrere Web-Ports gefunden werden)
MAX_CONCURRENT_WEB_SCANS = 2

# Wordlists
FAST_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
SLOW_WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
SUBDOMAIN_WORDLIST = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

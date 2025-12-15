import asyncio
import os
from utils import print_info, print_success, print_error, Colors

# Konfigurierbare Standard-Wordlist. 
# Für CTFs auf Kali Linux ist dies oft ein guter Startpunkt.
# Alternativen: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

async def run_gobuster(target, port, wordlist=DEFAULT_WORDLIST):
    """
    Führt gobuster dir auf dem angegebenen Target und Port aus.
    """
    # 1. Prüfen, ob Wordlist existiert
    if not os.path.exists(wordlist):
        print_error("GOBUSTER", f"Wordlist nicht gefunden: {wordlist}")
        print_info("GOBUSTER", "Bitte Pfad in modules/webscan.py anpassen oder Wordlist installieren.")
        return

    # 2. Protokoll bestimmen (HTTPS bei 443, sonst HTTP raten)
    # Für einen perfekten Scanner müsste man eigentlich prüfen, ob SSL läuft,
    # aber für einfache CTFs ist diese Heuristik meist ok.
    protocol = "https" if port in ['443', '8443'] else "http"
    base_url = f"{protocol}://{target}:{port}"

    print_info("GOBUSTER", f"Starte Web-Scan auf: {base_url}")

    # -k: Skip SSL verification
    # -q: Quiet (weniger Banner Output)
    # -t 50: Threads
    command = [
        "gobuster", "dir", 
        "-u", base_url, 
        "-w", wordlist, 
        "-k", 
        "-t", "50",
        "-q",
        "--no-error" # Keine Fehler bei Verbindungsabbruch sofort werfen
    ]
    
    # Befehl anzeigen (wie angefordert)
    print_info("EXEC", " ".join(command))

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Wir lesen den Output live, da Gobuster lange dauern kann
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            
            line_str = line.decode('utf-8').strip()
            
            if line_str:
                # Gobuster Output Formatierung
                # Format ist meist: /admin (Status: 301) [Size: 123]
                if "(Status: 200)" in line_str:
                     print_success(f"WEB-{port}", line_str)
                elif "(Status: 301)" in line_str or "(Status: 302)" in line_str:
                     print_info(f"WEB-{port}", f"{Colors.WARNING}{line_str}{Colors.ENDC}")
                elif "(Status: 403)" in line_str:
                     print_info(f"WEB-{port}", f"Forbidden: {line_str}")
                else:
                     print_info(f"WEB-{port}", line_str)

        await process.wait()
        
    except FileNotFoundError:
        print_error("GOBUSTER", "Gobuster ist nicht installiert! (apt install gobuster)")
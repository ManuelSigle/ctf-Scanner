import asyncio
import re
from utils import print_info, print_success, print_error, print_section, Colors

async def get_open_ports(target):
    """
    Phase 1: Scannt alle Ports (-p-) schnell.
    """
    print_info("NMAP-DISCOVERY", f"Suche nach offenen Ports auf {target}...")
    
    command = ["nmap", "-p-", "-T4", "-n", "--open", "-oG", "-", target]
    
    # NEU: Befehl anzeigen
    print_info("EXEC", " ".join(command))

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await process.communicate()
    
    if process.returncode != 0:
        print_error("NMAP-DISCOVERY", f"Fehler beim Scannen: {stderr.decode()}")
        return []

    output = stdout.decode()
    ports = []

    for line in output.splitlines():
        if "Ports:" in line:
            found = re.findall(r'(\d+)/open/tcp', line)
            ports.extend(found)

    ports = sorted(list(set(ports)), key=int)
    
    if ports:
        print_success("NMAP-DISCOVERY", f"Gefundene Ports: {', '.join(ports)}")
    else:
        print_info("NMAP-DISCOVERY", "Keine offenen TCP-Ports gefunden.")

    return ports

async def run_detailed_scan(target, ports):
    """
    Phase 2: Führt einen Detail-Scan (-A) aus.
    """
    if not ports:
        return None

    ports_str = ",".join(ports)
    print_info("NMAP-DETAIL", f"Starte Deep-Scan auf Ports: {ports_str}")

    command = ["nmap", "-A", "-T4", "-v", "-p", ports_str, target]
    
    # NEU: Befehl anzeigen
    print_info("EXEC", " ".join(command))

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await process.communicate()
    return stdout.decode()

def print_formatted_nmap(output):
    """
    Nimmt den rohen Nmap Output und gibt ihn schön formatiert aus.
    """
    if not output:
        return

    lines = output.splitlines()
    
    for line in lines:
        # Leere Zeilen überspringen, aber Formatierung beibehalten
        if not line.strip():
            continue

        # Header Zeilen (PORT STATE SERVICE VERSION)
        if line.startswith("PORT") and "STATE" in line:
            print(f"\n{Colors.BOLD}{Colors.HEADER}{line}{Colors.ENDC}")
        
        # Offene Ports (z.B. 22/tcp open ssh)
        elif "/tcp" in line and "open" in line:
            # Wir färben die ganze Zeile grün
            print_success("REPORT", line.strip())
            
        # Script Output (erkennbar am Pipe-Symbol | oder |_)
        elif line.strip().startswith("|"):
            # Script Output etwas einrücken und blau färben
            clean_line = line.strip()
            print_info("SCRIPT", clean_line)
            
        # OS Detection oder Service Info
        elif "Service Info" in line or "OS details" in line:
             print_info("INFO", f"{Colors.WARNING}{line.strip()}{Colors.ENDC}")
             
        # Warnungen von Nmap
        elif "WARNING:" in line:
             print_error("NMAP", line.strip())
             
        # Alles andere (z.B. Traceroute oder Header-Infos)
        else:
            # Zeige nur relevante Zeilen, ignoriere rohen Debug-Kram wenn nötig
            # Hier geben wir den Rest einfach eingerückt aus
            if not line.startswith("Nmap scan report"): # Den Header haben wir schon im Titel
                print(f"      {line}")
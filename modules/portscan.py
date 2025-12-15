import asyncio
import re
from utils import print_info, print_success, print_error, print_section, Colors

async def get_open_ports(target):
    """
    Phase 1: Scannt alle Ports (-p-) schnell.
    """
    print_info("NMAP-DISCOVERY", f"Suche nach offenen Ports auf {target}...")
    
    command = ["nmap", "-p-", "-T4", "-n", "--open", "-oG", "-", target]
    
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
    Mit Fortschrittsanzeige durch --stats-every.
    """
    if not ports:
        return None

    ports_str = ",".join(ports)
    print_info("NMAP-DETAIL", f"Starte Deep-Scan auf Ports: {ports_str}")

    # --stats-every 2s: Nmap gibt alle 2 Sekunden den Status aus
    command = ["nmap", "-A", "-T4", "-v", "--stats-every", "2s", "-p", ports_str, target]
    
    print_info("EXEC", " ".join(command))

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    # Wir sammeln den "sauberen" Output für den Report am Ende
    clean_output = []
    
    last_percentage_print = 0

    while True:
        line = await process.stdout.readline()
        if not line:
            break
        
        line_str = line.decode('utf-8')
        
        # Regex für Nmap Status Zeile: "Stats: 0:00:06 elapsed; ... About 5.00% done"
        stats_match = re.search(r"About ([\d\.]+)% done", line_str)
        
        if stats_match:
            try:
                percent = float(stats_match.group(1))
                # Wir geben nur alle 10% ein Update aus, um den Log nicht zu fluten
                if percent - last_percentage_print >= 10 or int(percent) == 5:
                    print_info("NMAP-STATUS", f"Scan Fortschritt: {int(percent)}% erledigt...")
                    last_percentage_print = percent
            except ValueError:
                pass
            
            # Statuszeilen NICHT in den finalen Report aufnehmen
            continue
            
        clean_output.append(line_str)

    await process.wait()
    return "".join(clean_output)

def print_formatted_nmap(output):
    """
    Nimmt den rohen Nmap Output und gibt ihn schön formatiert aus.
    """
    if not output:
        return

    lines = output.splitlines()
    
    for line in lines:
        if not line.strip():
            continue

        if line.startswith("PORT") and "STATE" in line:
            print(f"\n{Colors.BOLD}{Colors.HEADER}{line}{Colors.ENDC}")
        elif "/tcp" in line and "open" in line:
            print_success("REPORT", line.strip())
        elif line.strip().startswith("|"):
            clean_line = line.strip()
            print_info("SCRIPT", clean_line)
        elif "Service Info" in line or "OS details" in line:
             print_info("INFO", f"{Colors.WARNING}{line.strip()}{Colors.ENDC}")
        elif "WARNING:" in line:
             print_error("NMAP", line.strip())
        else:
            if not line.startswith("Nmap scan report"): 
                print(f"      {line}")
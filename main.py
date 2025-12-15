import asyncio
import argparse
import sys
from scanners.port_scanner import get_open_ports, run_detailed_scan, print_formatted_nmap
from scanners.web_scanner import run_web_recon
from scanners.subdomain_scanner import run_subdomain_recon
from core.utils import Colors, print_section, print_info
from core.config import WEB_PORTS, MAX_CONCURRENT_WEB_SCANS

def parse_args():
    parser = argparse.ArgumentParser(description="Custom CTF Recon Scanner")
    parser.add_argument("target", help="IP Adresse oder Hostname des Ziels")
    return parser.parse_args()

async def main():
    args = parse_args()
    
    print_section(f"TARGET: {args.target}")

    # --- SCHRITT 1: Ports finden (Nmap Discovery) ---
    # Wir warten, bis dieser Schritt komplett fertig ist.
    open_ports = await get_open_ports(args.target)

    if not open_ports:
        print("Abbruch: Keine Ports gefunden.")
        return

    # --- SCHRITT 2: Services Scannen (Nmap Detail) ---
    # Wir warten, bis Nmap -A komplett durchgelaufen ist.
    # Währenddessen siehst du die %-Anzeige aus portscan.py
    nmap_result = await run_detailed_scan(args.target, open_ports)
    
    # --- SCHRITT 3: Nmap Report sofort ausgeben ---
    # Jetzt hast du erst mal Zeit, die Nmap Ergebnisse zu lesen.
    print_section("NMAP REPORT")
    print_formatted_nmap(nmap_result)
    print_section("NMAP FINISHED")

    # --- SCHRITT 4: Web Recon (Gobuster) ---
    # Erst JETZT schauen wir nach Webservern und starten Gobuster.
    
    found_web_ports = [p for p in open_ports if p in WEB_PORTS]
    
    if found_web_ports:
        print_section("STARTING WEB RECON")
        print_info("MAIN", f"Web-Ports erkannt: {', '.join(found_web_ports)}")
        print_info("MAIN", f"Starte Scans nacheinander (Max {MAX_CONCURRENT_WEB_SCANS} parallel)...")
        
        web_tasks = []
        web_semaphore = asyncio.Semaphore(MAX_CONCURRENT_WEB_SCANS)
        
        for port in found_web_ports:
            # Task erstellen
            task = run_web_recon(args.target, port, web_semaphore)
            web_tasks.append(task)
            
        # Wir warten, bis alle Web-Scans fertig sind
        await asyncio.gather(*web_tasks)
        
    else:
        print_info("MAIN", "Keine Web-Ports erkannt. Überspringe Web-Recon.")

    # --- SCHRITT 5: Subdomain Recon (Gobuster DNS) ---
    print_section("STARTING SUBDOMAIN RECON")
    await run_subdomain_recon(args.target)

    print_section("ALL SCANS FINISHED")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Abbruch durch Benutzer.")

import asyncio
import argparse
import sys
from modules.portscan import get_open_ports, run_detailed_scan, print_formatted_nmap
from utils import Colors, print_section

def parse_args():
    parser = argparse.ArgumentParser(description="Custom CTF Recon Scanner")
    parser.add_argument("target", help="IP Adresse oder Hostname des Ziels")
    return parser.parse_args()

async def main():
    args = parse_args()
    
    print_section(f"TARGET: {args.target}")

    # --- SCHRITT 1: Ports finden ---
    open_ports = await get_open_ports(args.target)

    if not open_ports:
        print("Abbruch: Keine Ports für weiteren Scan gefunden.")
        return

    # --- SCHRITT 2: Details scannen ---
    # nmap -A Scan
    scan_result = await run_detailed_scan(args.target, open_ports)

    # --- SCHRITT 3: Ergebnis Ausgabe ---
    print_section("NMAP REPORT")
    
    # Hier nutzen wir jetzt den neuen Formatter
    print_formatted_nmap(scan_result)
    
    print_section("SCAN FINISHED")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Abbruch durch Benutzer.")
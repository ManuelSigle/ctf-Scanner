import asyncio
import os
import time
from core.utils import print_info, print_success, print_error, Colors
from core.config import FAST_WORDLIST, SLOW_WORDLIST

async def _monitor_process(label, interval=15):
    """
    Ein Heartbeat, der anzeigt, dass der Scan noch läuft.
    """
    start_time = time.time()
    while True:
        await asyncio.sleep(interval)
        elapsed = int(time.time() - start_time)
        print_info(label, f"... Scan läuft noch ({elapsed}s vergangen) ...")

async def _execute_gobuster(target_url, wordlist, label, known_paths=None):
    """
    Hilfsfunktion, die EINEN Gobuster-Prozess ausführt.
    """
    if not os.path.exists(wordlist):
        print_error(label, f"Wordlist fehlt: {wordlist} - Überspringe Scan.")
        return set()

    print_info(label, f"Starte Scan mit {wordlist}...")
    
    command = [
        "gobuster", "dir", 
        "-u", target_url, 
        "-w", wordlist, 
        "-k", "-t", "40", "-q", "--no-error"
    ]
    
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    # Starte den Heartbeat-Monitor im Hintergrund
    monitor_task = asyncio.create_task(_monitor_process(label))

    new_findings = set()

    try:
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            
            line_str = line.decode('utf-8').strip()
            if not line_str:
                continue

            path = line_str.split(' ')[0]

            if known_paths is not None and path in known_paths:
                continue 

            new_findings.add(path)

            prefix = "[NEW]" if known_paths is not None else ""
            
            if "(Status: 200)" in line_str:
                 print_success(label, f"{prefix} {line_str}")
            elif "(Status: 403)" in line_str:
                 print_info(label, f"{Colors.WARNING}{prefix} Forbidden: {path}{Colors.ENDC}")
            else:
                 print_info(label, f"{prefix} {line_str}")
    finally:
        # Wichtig: Monitor beenden, wenn der Prozess fertig ist
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass

    await process.wait()
    return new_findings

async def run_web_recon(target, port, semaphore):
    """
    Hauptfunktion für den Web-Scan. Führt nacheinander Fast- und Slow-Scan aus.
    """
    protocol = "https" if port in ['443', '8443'] else "http"
    base_url = f"{protocol}://{target}:{port}"
    identifier = f"WEB-{port}"

    async with semaphore:
        # PHASE 1
        print_info(identifier, f"Start Phase 1: Fast Scan ({base_url})")
        found_paths = await _execute_gobuster(
            base_url, 
            FAST_WORDLIST, 
            f"{identifier}-FAST"
        )
        
        if not found_paths:
            print_info(identifier, "Fast Scan lieferte keine Ergebnisse.")

        # PHASE 2
        if os.path.exists(SLOW_WORDLIST):
            print_info(identifier, f"Start Phase 2: Deep Scan (Nur neue Ergebnisse anzeigen)")
            await _execute_gobuster(
                base_url, 
                SLOW_WORDLIST, 
                f"{identifier}-DEEP",
                known_paths=found_paths
            )
        else:
            print_info(identifier, "Große Wordlist nicht gefunden, überspringe Phase 2.")
            
        print_success(identifier, "Web Recon abgeschlossen.")

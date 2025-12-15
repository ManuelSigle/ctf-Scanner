import asyncio
import os
import time
from core.utils import print_info, print_success, print_error, Colors
from core.config import SUBDOMAIN_WORDLIST

async def _monitor_process(label, interval=15):
    """
    Ein Heartbeat, der anzeigt, dass der Scan noch läuft.
    """
    start_time = time.time()
    while True:
        await asyncio.sleep(interval)
        elapsed = int(time.time() - start_time)
        print_info(label, f"... Scan läuft noch ({elapsed}s vergangen) ...")

async def run_subdomain_recon(target):
    """
    Führt Subdomain-Enumeration mit Gobuster DNS aus.
    """
    label = "SUBDOMAIN-RECON"

    if not os.path.exists(SUBDOMAIN_WORDLIST):
        print_info(label, f"Wordlist fehlt: {SUBDOMAIN_WORDLIST} - Überspringe Subdomain Scan.")
        # Wir versuchen es trotzdem, wenn der User eine andere Wordlist will?
        # Aber hier nehmen wir erst mal die aus der Config.
        return

    print_section_header = f"STARTING SUBDOMAIN RECON ({target})"
    print_info(label, print_section_header)

    command = [
        "gobuster", "dns",
        "-d", target,
        "-w", SUBDOMAIN_WORDLIST,
        "-t", "50",
        "-q", "--no-error"
    ]

    print_info("EXEC", " ".join(command))

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    monitor_task = asyncio.create_task(_monitor_process(label))

    try:
        while True:
            line = await process.stdout.readline()
            if not line:
                break

            line_str = line.decode('utf-8').strip()
            if not line_str:
                continue

            if "Found:" in line_str:
                # Gobuster DNS output format: "Found: sub.example.com"
                clean_line = line_str.replace("Found: ", "").strip()
                print_success(label, clean_line)
            else:
                print_info(label, line_str)

    finally:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass

    await process.wait()
    print_success(label, "Subdomain Recon abgeschlossen.")

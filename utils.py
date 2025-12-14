class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_info(source, message):
    print(f"{Colors.BLUE}[*] [{source}]{Colors.ENDC} {message}")

def print_success(source, message):
    print(f"{Colors.GREEN}[+] [{source}]{Colors.ENDC} {message}")

def print_error(source, message):
    print(f"{Colors.FAIL}[!] [{source}]{Colors.ENDC} {message}")

def print_section(title):
    print(f"\n{Colors.HEADER}{'='*10} {title} {'='*10}{Colors.ENDC}")
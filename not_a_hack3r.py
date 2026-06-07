# - any use of this is for ethical use and not intended for malicious activity.
# hAckDHD
# My un-vibecode edition
# For Kali, Parrot, or any Debian-based distro

##########################################
# //////          Imports          //////#
##########################################

import os
import socket
import getpass
import subprocess
import curses
from pathlib import Path
from datetime import datetime
import shutil
import time
import threading

##########################################
# //////           COLOR           //////#
##########################################
RED   = "\033[31m"
RESET = "\033[0m"
BLUE  = "\033[36m"

##########################################
def colorlogic(value):
    return BLUE if value else RED

##########################################
# //////         User Info         ######
##########################################
USER     = getpass.getuser()
BASE_DIR = Path(f"/home/{USER}/ENGAGEMENTS")
BASE_DIR.mkdir(parents=True, exist_ok=True)
ACTIVE_FILE = BASE_DIR / ".active"

##########################################
# //////            Ip Info         ####
##########################################
LOCAL_IP    = "Unknown"
PUBLIC_IP   = "Unknown"
TARGET_IP   = ""
TARGET_WEB  = ""
CURRENT_ENG = ""
ENG_PATH    = None
ENG_NAME    = None

##########################################
# //////            ASCII ART       ####
##########################################
ASCII_ART = r"""
 __ _   __  ____        __         _  _   __    ___  __ _  ____  ____
(  ( \ /  \(_  _)      / _\       / )( \ / _\  / __)(  / )(  __)(  _ \
/    /(  O ) )(  _____/    \ ____ ) __ (/    \( (__  )  (  ) _)  )   /
\_)__) \__/ (__)(____)\_/\_/(____)\_)(_/\_/\_/ \___)(__\_)(____)(__\_)
"""

##########################################
# //////       CHECKMARK SYSTEM    ######
##########################################
tcp_done        = False
udp_fast_done   = False
udp_full_done   = False
tcp_full_done   = False
tcp_banner_done = False
udp_banner_done = False
snmp_done       = False

def checkmark(state: bool, engagement_active: bool = True):
    if not engagement_active:
        return " "
    return f"{BLUE}✔{RESET}" if state else f"{RED}✘{RESET}"


##########################################
# //////     TERMINAL LAUNCHER     ######
##########################################
def launch_in_terminal(script_path: Path):
    """
    Detect whatever terminal emulator is available on this Debian-based
    system and launch the given shell script in a new window.
    Falls back to xterm which is available on virtually every distro.
    """
    candidates = [
        "mate-terminal",
        "xfce4-terminal",
        "gnome-terminal",
        "konsole",
        "lxterminal",
        "tilix",
        "terminator",
        "kitty",
        "alacritty",
        "xterm",          # universal fallback — install via: sudo apt install xterm
    ]

    term = None
    for c in candidates:
        found = shutil.which(c)
        if found:
            term = found
            break

    if not term:
        print(f"{RED}No terminal emulator found.{RESET}")
        print(f"Install one with:  sudo apt install xterm -y")
        print(f"Or run manually:   bash {script_path}")
        input("Press Enter to continue...")
        return

    name = Path(term).name

    # gnome-terminal uses -- to separate its args from the command
    if name == "gnome-terminal":
        cmd = [term, "--", "bash", str(script_path)]
    # these use --command with a string (not a list)
    elif name in ("xfce4-terminal",):
        cmd = [term, "--command", f"bash {script_path}"]
    # everything else (mate-terminal, xterm, lxterminal, tilix,
    # terminator, kitty, alacritty, konsole) uses -e
    else:
        cmd = [term, "-e", f"bash {script_path}"]

    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


##########################################
# //////       PRINT FUNCTIONS    ######
##########################################
def print_center(text):
    width = shutil.get_terminal_size().columns
    for line in text.split("\n"):
        print(line.center(width))

def print_line(char="-"):
    width = shutil.get_terminal_size().columns
    print(char * width)


##########################################
# //////       SHELL / IP          ######
##########################################
def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
    except:
        return ""

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "Unknown"

def get_public_ip():
    services = [
        ["curl", "-4", "-s", "--max-time", "3", "https://api.ipify.org"],
        ["curl", "-4", "-s", "--max-time", "3", "https://ifconfig.me/ip"],
        ["curl", "-4", "-s", "--max-time", "3", "https://icanhazip.com"],
        ["curl", "-4", "-s", "--max-time", "3", "https://checkip.amazonaws.com"],
    ]
    for s in services:
        ip = run_cmd(s)
        if ip and "." in ip:
            return ip.strip()
    return "Unknown"

def refresh_ips():
    global LOCAL_IP, PUBLIC_IP
    LOCAL_IP  = get_local_ip()
    PUBLIC_IP = get_public_ip()
    refresh_scan_status()

def refresh_scan_status():
    global tcp_done, udp_fast_done, udp_full_done, tcp_full_done
    global tcp_banner_done, udp_banner_done, snmp_done
    if not ENG_PATH or not TARGET_IP:
        return
    scan_dir        = Path(f"{ENG_PATH}/recon_scans")
    tcp_done        = (scan_dir / f"NMAP_{TARGET_IP}_TCP_General.nmap").exists()
    udp_fast_done   = (scan_dir / f"NMAP_{TARGET_IP}_UDP_Fast.nmap").exists()
    udp_full_done   = (scan_dir / f"NMAP_{TARGET_IP}_UDP_Full.nmap").exists()
    tcp_full_done   = (scan_dir / f"NMAP_{TARGET_IP}_TCP_Full.nmap").exists()
    tcp_banner_done = (scan_dir / f"NMAP_{TARGET_IP}_TCP_Banner.nmap").exists()
    udp_banner_done = (scan_dir / f"NMAP_{TARGET_IP}_UDP_Banner.nmap").exists()
    snmp_done       = (scan_dir / f"SNMP_WALK_{TARGET_IP}.txt").exists()

def load_active():
    global ENG_PATH, CURRENT_ENG, TARGET_IP, TARGET_WEB
    if ACTIVE_FILE.exists():
        ENG_PATH    = Path(ACTIVE_FILE.read_text().strip())
        ipf         = ENG_PATH / "target_info" / "target_ip.txt"
        webf        = ENG_PATH / "target_info" / "target_web.txt"
        CURRENT_ENG = ENG_PATH
        if ipf.exists():
            TARGET_IP  = ipf.read_text().strip()
        if webf.exists():
            TARGET_WEB = webf.read_text().strip()

def check_leak():
    cmd = f"curl https://raw.githubusercontent.com/macvk/dnsleaktest/master/dnsleaktest.sh -o /home/{USER}/engagmentscripts/dnsleaktest.sh | grep Conclusion"
    dns_result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(dns_result.stdout)


##########################################
# //////     ENGAGEMENT MGMT       ######
##########################################
def choose_engagement():
    global ENG_PATH
    dirs = [d for d in BASE_DIR.iterdir() if d.is_dir()]
    print("\nEngagements:")
    for i, d in enumerate(dirs, 1):
        print(f"{i}) {d.name}")
    print(f"{len(dirs) + 1}) New Engagement")

    c = input("Select: ")
    if not c.isdigit():
        return
    c = int(c)

    if 1 <= c <= len(dirs):
        ENG_PATH = dirs[c - 1]
    else:
        name     = input("New engagement name: ")
        ENG_PATH = BASE_DIR / name
        ENG_PATH.mkdir(parents=True, exist_ok=True)
        (ENG_PATH / "scripts").mkdir(parents=True, exist_ok=True)
        (ENG_PATH / "recon_scans").mkdir(parents=True, exist_ok=True)
        (ENG_PATH / "target_info").mkdir(parents=True, exist_ok=True)
        set_target_ip()
        set_target_web()
        load_active()
    ACTIVE_FILE.write_text(str(ENG_PATH))
    load_active()

def set_target_ip():
    global TARGET_IP
    if not ENG_PATH:
        return
    ipf       = ENG_PATH / "target_info" / "target_ip.txt"
    TARGET_IP = input("Target IP: ").strip()
    ipf.write_text(TARGET_IP)

def set_target_web():
    global TARGET_WEB
    if not ENG_PATH:
        return
    webf       = ENG_PATH / "target_info" / "target_web.txt"
    TARGET_WEB = input("Target Web: ").strip()
    webf.write_text(TARGET_WEB)

def exit_engagement():
    global ENG_PATH, TARGET_IP, TARGET_WEB
    ENG_PATH   = None
    TARGET_IP  = ""
    TARGET_WEB = ""
    if ACTIVE_FILE.exists():
        ACTIVE_FILE.unlink()

def host_status():
    if not TARGET_IP:
        return f"{RED}no_engagement{RESET}"
    with open("/etc/hosts") as f:
        for line in f:
            if TARGET_IP in line:
                return f"{BLUE}yes{RESET}"
    return f"{RED}no{RESET}"

def add_host():
    if TARGET_IP and TARGET_WEB:
        os.system(f"echo '{TARGET_IP} {TARGET_WEB}' | sudo tee -a /etc/hosts")

def remove_host():
    if TARGET_IP:
        os.system(f"sudo sed -i '/{TARGET_IP}/d' /etc/hosts")

def move_engagement():
    global ENG_PATH
    if not ENG_PATH or not ENG_PATH.exists():
        print(f"{RED}No active engagement to move.{RESET}")
        return
    complete_dir = BASE_DIR / "COMPLETE"
    complete_dir.mkdir(parents=True, exist_ok=True)
    dest = complete_dir / ENG_PATH.name
    try:
        shutil.move(str(ENG_PATH), str(dest))
        remove_host()
        exit_engagement()
    except Exception as e:
        print(f"{RED}Failed to move engagement: {e}{RESET}")


# ////////////////////////////////////////////////////////#
#                                                        #
#                    PRE-REQUISITES                      #
#                                                        #
#  Checks and installs all tools used by this script.   #
#  Works on any Debian-based distro (Kali, Parrot, etc) #
#                                                        #
# ////////////////////////////////////////////////////////#

# Each entry: (display_name, apt_package, binary_to_check)
PREREQ_TOOLS = [
    # Core scanning
    ("nmap",            "nmap",                    "nmap"),
    ("curl",            "curl",                    "curl"),
    ("snmpwalk",        "snmp",                    "snmpwalk"),
    # Web enum
    ("ffuf",            "ffuf",                    "ffuf"),
    # Terminal emulator (universal fallback)
    ("xterm",           "xterm",                   "xterm"),
    # Wordlists (seclists)
    ("seclists",        "seclists",                None),   # no binary, check dir
    # Useful extras
    ("gobuster",        "gobuster",                "gobuster"),
    ("nikto",           "nikto",                   "nikto"),
    ("whatweb",         "whatweb",                 "whatweb"),
    ("dnsrecon",        "dnsrecon",                "dnsrecon"),
    ("enum4linux",      "enum4linux",              "enum4linux"),
    ("smbclient",       "smbclient",               "smbclient"),
    ("impacket scripts","python3-impacket",         None),  # check via python import
    ("hydra",           "hydra",                   "hydra"),
    ("john",            "john",                    "john"),
    ("hashcat",         "hashcat",                 "hashcat"),
    ("netcat",          "netcat-traditional",      "nc"),
    ("socat",           "socat",                   "socat"),
    ("python3-pip",     "python3-pip",             "pip3"),
    ("git",             "git",                     "git"),
]

def check_tool(binary, pkg):
    """Return True if a tool is present."""
    if binary:
        return shutil.which(binary) is not None
    # Special cases with no binary
    if pkg == "seclists":
        return Path("/usr/share/wordlists/seclists").exists()
    if pkg == "python3-impacket":
        try:
            import impacket  # noqa: F401
            return True
        except ImportError:
            return False
    return False

def prereqs():
    while True:
        os.system("clear")
        print(f"{BLUE}[ Pre-Requisites Check ]{RESET}\n")
        print(f"{'Tool':<22} {'Status'}")
        print("-" * 40)

        missing = []
        for display, pkg, binary in PREREQ_TOOLS:
            installed = check_tool(binary, pkg)
            status    = f"{BLUE}✔ installed{RESET}" if installed else f"{RED}✘ missing{RESET}"
            print(f"{display:<22} {status}")
            if not installed:
                missing.append((display, pkg))

        print()
        if not missing:
            print(f"{BLUE}All tools are installed.{RESET}\n")
            input("Press Enter to return to main menu...")
            break

        print(f"{RED}{len(missing)} tool(s) missing.{RESET}\n")
        print("1) Install all missing tools")
        print("2) Refresh check")
        print("3) Back to main menu\n")

        c = input("Select: ").strip()

        if c == "1":
            os.system("clear")
            print(f"{BLUE}[ Installing missing tools ]{RESET}\n")
            print("Updating apt cache...\n")
            os.system("sudo apt update -y")
            print()

            pkgs = " ".join(pkg for _, pkg in missing)
            print(f"{BLUE}Installing:{RESET} {pkgs}\n")
            ret = os.system(f"sudo apt install -y {pkgs}")

            # pip-based tools that may not be in apt
            pip_extras = {
                "python3-impacket": "impacket",
            }
            for display, pkg in missing:
                if pkg in pip_extras:
                    print(f"\n{BLUE}Installing {display} via pip...{RESET}")
                    os.system(f"sudo pip3 install {pip_extras[pkg]} --break-system-packages 2>/dev/null || sudo pip3 install {pip_extras[pkg]}")

            print()
            if ret == 0:
                print(f"{BLUE}Installation complete.{RESET}")
            else:
                print(f"{RED}Some packages may have failed. Check output above.{RESET}")
            input("\nPress Enter to refresh check...")

        elif c == "2":
            continue

        elif c == "3":
            break


# ////////////////////////////////////////////////////////#
#                                                        #
#                       RECON                            #
#                                                        #
#  Both HTB and LIVE write a self-contained dashboard    #
#  script to disk then launch it in a new terminal via   #
#  launch_in_terminal(). The dashboard script contains   #
#  everything it needs - scan list, curses UI, threading #
#  - so it runs fully independently in its own window.   #
#                                                        #
#  HTB  - parallel:   all scans fire at once             #
#  LIVE - sequential: one scan at a time in order        #
#                                                        #
# ////////////////////////////////////////////////////////#

def recon():
    while True:
        os.system("clear")
        print("What type of engagement")
        print("1) HTB/CTF")
        print("2) LIVE")
        print("3) MAIN MENU")

        c = input("Select: ").lower()

        # -------------------------------------------------- HTB / CTF
        if c == "1":
            if not ENG_PATH or not TARGET_IP:
                input(f"{RED}No engagement or target set. Press Enter...{RESET}")
                break

            scan_dir    = Path(f"{ENG_PATH}/recon_scans")
            scripts_dir = Path(f"{ENG_PATH}/scripts")
            scan_dir.mkdir(parents=True, exist_ok=True)
            scripts_dir.mkdir(parents=True, exist_ok=True)

            scans = [
                ("TCP General", f"sudo nmap -sC -sV -vv {TARGET_IP} -oA {ENG_PATH}/recon_scans/NMAP_{TARGET_IP}_TCP_General"),
                ("UDP Fast",    f"sudo nmap -sU -p 53,161,67,68,123,137,138,139,162,445 -sV -vv {TARGET_IP} -oA {ENG_PATH}/recon_scans/NMAP_{TARGET_IP}_UDP_Fast"),
                ("UDP Full",    f"sudo nmap -sU -p- -sV -vv {TARGET_IP} -oA {ENG_PATH}/recon_scans/NMAP_{TARGET_IP}_UDP_Full"),
                ("TCP Full",    f"sudo nmap -p- -sV -vv {TARGET_IP} -oA {ENG_PATH}/recon_scans/NMAP_{TARGET_IP}_TCP_Full"),
                ("TCP Banner",  f"sudo nmap -sC -sV -vv {TARGET_IP} --script=banner -oA {ENG_PATH}/recon_scans/NMAP_{TARGET_IP}_TCP_Banner"),
                ("UDP Banner",  f"sudo nmap -sU -sV -vv {TARGET_IP} --script=banner -oA {ENG_PATH}/recon_scans/NMAP_{TARGET_IP}_UDP_Banner"),
                ("SNMP Walk",   f"snmpwalk -v2c -c public {TARGET_IP} > {ENG_PATH}/recon_scans/SNMP_WALK_{TARGET_IP}.txt"),
            ]

            os.system("clear")
            print(f"{BLUE}[ HTB/CTF Recon ]{RESET} Target: {TARGET_IP}")
            print(f"\nAll {len(scans)} scans will fire simultaneously in a new window.")
            print("Each sudo command will prompt for your password in the scan window.\n")
            input("Press Enter to launch...")
            time.sleep(0.3)

            dashboard_script = scripts_dir / "recon_htb_dashboard.py"
            dashboard_script.write_text(f"""\
import subprocess, threading, curses, time, os, getpass, sys

TARGET_IP = {repr(TARGET_IP)}

scans = {repr(scans)}

print("\\033[36m[ HTB/CTF Recon - {TARGET_IP} ]\\033[0m")
print("\\nEnter sudo password once - all scans will use it.\\n")
try:
    SUDO_PW = getpass.getpass("sudo password: ")
except KeyboardInterrupt:
    print("\\nCancelled.")
    sys.exit(1)

test = subprocess.run(
    ["sudo", "-S", "-v"],
    input=SUDO_PW + "\\n",
    capture_output=True,
    text=True
)
if test.returncode != 0:
    print("\\033[31mIncorrect password or sudo failed. Exiting.\\033[0m")
    input("Press Enter to close...")
    sys.exit(1)

print("\\033[36mAuth OK. Starting scans...\\033[0m\\n")
time.sleep(0.5)

status       = {{name: "PENDING" for name, _ in scans}}
output_lines = []
lock         = threading.Lock()
all_done     = threading.Event()

def run_scan(name, cmd):
    injected_cmd = cmd.replace("sudo ", "sudo -S ", 1)
    with lock:
        status[name] = "RUNNING"
    proc = subprocess.Popen(
        injected_cmd, shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    try:
        proc.stdin.write(SUDO_PW + "\\n")
        proc.stdin.flush()
        proc.stdin.close()
    except BrokenPipeError:
        pass
    for line in proc.stdout:
        with lock:
            output_lines.append(f"[{{name}}] {{line.rstrip()}}")
    proc.wait()
    with lock:
        status[name] = "DONE"

def launch_all():
    threads = [threading.Thread(target=run_scan, args=(n, c), daemon=True)
               for n, c in scans]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    all_done.set()

threading.Thread(target=launch_all, daemon=True).start()

def draw_ui(stdscr):
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN,   -1)
    curses.init_pair(2, curses.COLOR_RED,    -1)
    curses.init_pair(3, curses.COLOR_GREEN,  -1)
    curses.init_pair(4, curses.COLOR_YELLOW, -1)
    curses.curs_set(0)
    stdscr.nodelay(True)

    CYAN   = curses.color_pair(1)
    RED    = curses.color_pair(2)
    GREEN  = curses.color_pair(3)
    YELLOW = curses.color_pair(4)
    BOLD   = curses.A_BOLD

    while True:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        split      = int(width * 0.60)
        status_col = split + 2

        try:
            stdscr.addstr(0, 0, f"[ Live Output - {{TARGET_IP}} ] HTB/CTF - ALL SCANS PARALLEL", CYAN | BOLD)
            stdscr.addstr(1, 0, "-" * (split - 1))
        except curses.error:
            pass

        with lock:
            visible = output_lines[-(height - 3):]
        for i, line in enumerate(visible, start=2):
            if i >= height - 1:
                break
            try:
                stdscr.addstr(i, 0, line[:split - 1])
            except curses.error:
                pass

        for row in range(height):
            try:
                stdscr.addch(row, split, ord("|"))
            except curses.error:
                pass

        try:
            stdscr.addstr(0, status_col, "[ Scan Status ]", CYAN | BOLD)
            stdscr.addstr(1, status_col, "-" * (width - status_col - 1))
        except curses.error:
            pass

        with lock:
            cur = dict(status)
        for i, (name, _) in enumerate(scans, start=3):
            if i >= height - 1:
                break
            state = cur.get(name, "PENDING")
            if state == "DONE":
                color, icon = GREEN,  "OK"
            elif state == "RUNNING":
                color, icon = YELLOW, ">>"
            else:
                color, icon = RED,    "--"
            try:
                stdscr.addstr(i, status_col,      f"{{icon}} {{name:<15}}", color | BOLD)
                stdscr.addstr(i, status_col + 18, f"[ {{state}} ]",         color)
            except curses.error:
                pass

        done_count = sum(1 for s in cur.values() if s == "DONE")
        total      = len(scans)
        footer     = f" {{done_count}}/{{total}} complete | press q to close " if all_done.is_set() else f" {{done_count}}/{{total}} complete | running... "
        try:
            stdscr.addstr(height - 1, 0, footer[:width - 1], CYAN | BOLD)
        except curses.error:
            pass

        stdscr.refresh()
        key = stdscr.getch()
        if key == ord("q") and all_done.is_set():
            break
        time.sleep(0.5)

curses.wrapper(draw_ui)
print("\\nAll scans complete.")
input("Press Enter to close...")
""")

            launcher = Path("/tmp/hackdhd_htb_recon.sh")
            launcher.write_text(f"#!/bin/bash\npython3 {dashboard_script}\n")
            launcher.chmod(0o755)
            launch_in_terminal(launcher)
            break

        # -------------------------------------------------- LIVE
        elif c == "2":
            if not ENG_PATH or not TARGET_IP:
                input(f"{RED}No engagement or target set. Press Enter...{RESET}")
                break

            scan_dir    = Path(f"{ENG_PATH}/recon_scans")
            scripts_dir = Path(f"{ENG_PATH}/scripts")
            scan_dir.mkdir(parents=True, exist_ok=True)
            scripts_dir.mkdir(parents=True, exist_ok=True)

            scans = [
                ("TCP General", f"sudo nmap -sC -sV -T2 -vv {TARGET_IP} -oA {ENG_PATH}/recon_scans/NMAP_{TARGET_IP}_TCP_General"),
                ("UDP Fast",    f"sudo nmap -sU -p 53,161,67,68,123,137,138,139,162,445 -sV -T2 -vv {TARGET_IP} -oA {ENG_PATH}/recon_scans/NMAP_{TARGET_IP}_UDP_Fast"),
                ("SNMP Walk",   f"snmpwalk -v2c -c public {TARGET_IP} > {ENG_PATH}/recon_scans/SNMP_WALK_{TARGET_IP}.txt"),
                ("TCP Full",    f"sudo nmap -p- -sV -T2 -vv {TARGET_IP} -oA {ENG_PATH}/recon_scans/NMAP_{TARGET_IP}_TCP_Full"),
                ("UDP Full",    f"sudo nmap -sU -p- -sV -T2 -vv {TARGET_IP} -oA {ENG_PATH}/recon_scans/NMAP_{TARGET_IP}_UDP_Full"),
                ("TCP Banner",  f"sudo nmap -sC -sV -T2 -vv {TARGET_IP} --script=banner -oA {ENG_PATH}/recon_scans/NMAP_{TARGET_IP}_TCP_Banner"),
                ("UDP Banner",  f"sudo nmap -sU -sV -T2 -vv {TARGET_IP} --script=banner -oA {ENG_PATH}/recon_scans/NMAP_{TARGET_IP}_UDP_Banner"),
            ]

            os.system("clear")
            print(f"{BLUE}[ LIVE Engagement Recon ]{RESET} Target: {TARGET_IP}")
            print(f"\nScans will run one at a time in order in a new window.")
            print(f"Timing set to {BLUE}-T2 (Polite){RESET} to reduce noise on a live host.\n")
            print("Order:")
            for i, (name, _) in enumerate(scans, 1):
                print(f"  {i}) {name}")
            print(f"\n{RED}WARNING:{RESET} Ensure you have written authorisation before proceeding.\n")
            input("Press Enter to launch...")
            time.sleep(0.3)

            dashboard_script = scripts_dir / "recon_live_dashboard.py"
            dashboard_script.write_text(f"""\
import subprocess, threading, curses, time, os, getpass, sys

TARGET_IP = {repr(TARGET_IP)}

scans = {repr(scans)}

print("\\033[36m[ LIVE Recon - {TARGET_IP} ]\\033[0m")
print("\\nEnter sudo password once - all scans will use it.\\n")
try:
    SUDO_PW = getpass.getpass("sudo password: ")
except KeyboardInterrupt:
    print("\\nCancelled.")
    sys.exit(1)

test = subprocess.run(
    ["sudo", "-S", "-v"],
    input=SUDO_PW + "\\n",
    capture_output=True,
    text=True
)
if test.returncode != 0:
    print("\\033[31mIncorrect password or sudo failed. Exiting.\\033[0m")
    input("Press Enter to close...")
    sys.exit(1)

print("\\033[36mAuth OK. Starting scans...\\033[0m\\n")
time.sleep(0.5)

status       = {{name: "PENDING" for name, _ in scans}}
output_lines = []
lock         = threading.Lock()
all_done     = threading.Event()

def run_all_sequential():
    for name, cmd in scans:
        injected_cmd = cmd.replace("sudo ", "sudo -S ", 1)
        with lock:
            status[name] = "RUNNING"
        proc = subprocess.Popen(
            injected_cmd, shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        try:
            proc.stdin.write(SUDO_PW + "\\n")
            proc.stdin.flush()
            proc.stdin.close()
        except BrokenPipeError:
            pass
        for line in proc.stdout:
            with lock:
                output_lines.append(f"[{{name}}] {{line.rstrip()}}")
        proc.wait()
        with lock:
            status[name] = "DONE"
    all_done.set()

threading.Thread(target=run_all_sequential, daemon=True).start()

def draw_ui(stdscr):
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN,   -1)
    curses.init_pair(2, curses.COLOR_RED,    -1)
    curses.init_pair(3, curses.COLOR_GREEN,  -1)
    curses.init_pair(4, curses.COLOR_YELLOW, -1)
    curses.curs_set(0)
    stdscr.nodelay(True)

    CYAN   = curses.color_pair(1)
    RED    = curses.color_pair(2)
    GREEN  = curses.color_pair(3)
    YELLOW = curses.color_pair(4)
    BOLD   = curses.A_BOLD

    while True:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        split      = int(width * 0.60)
        status_col = split + 2

        try:
            stdscr.addstr(0, 0, f"[ Live Output - {{TARGET_IP}} ] LIVE - ONE AT A TIME", CYAN | BOLD)
            stdscr.addstr(1, 0, "-" * (split - 1))
        except curses.error:
            pass

        with lock:
            visible = output_lines[-(height - 3):]
        for i, line in enumerate(visible, start=2):
            if i >= height - 1:
                break
            try:
                stdscr.addstr(i, 0, line[:split - 1])
            except curses.error:
                pass

        for row in range(height):
            try:
                stdscr.addch(row, split, ord("|"))
            except curses.error:
                pass

        try:
            stdscr.addstr(0, status_col, "[ Scan Queue ]", CYAN | BOLD)
            stdscr.addstr(1, status_col, "-" * (width - status_col - 1))
        except curses.error:
            pass

        with lock:
            cur = dict(status)
        for i, (name, _) in enumerate(scans, start=3):
            if i >= height - 1:
                break
            state = cur.get(name, "PENDING")
            if state == "DONE":
                color, icon = GREEN,  "OK"
            elif state == "RUNNING":
                color, icon = YELLOW, ">>"
            else:
                color, icon = RED,    "--"
            try:
                stdscr.addstr(i, status_col,      f"{{icon}} {{name:<15}}", color | BOLD)
                stdscr.addstr(i, status_col + 18, f"[ {{state}} ]",         color)
            except curses.error:
                pass

        done_count = sum(1 for s in cur.values() if s == "DONE")
        total      = len(scans)
        footer     = f" {{done_count}}/{{total}} complete | press q to close " if all_done.is_set() else f" {{done_count}}/{{total}} complete | running... "
        try:
            stdscr.addstr(height - 1, 0, footer[:width - 1], CYAN | BOLD)
        except curses.error:
            pass

        stdscr.refresh()
        key = stdscr.getch()
        if key == ord("q") and all_done.is_set():
            break
        time.sleep(0.5)

curses.wrapper(draw_ui)
print("\\nAll scans complete.")
input("Press Enter to close...")
""")

            launcher = Path("/tmp/hackdhd_live_recon.sh")
            launcher.write_text(f"#!/bin/bash\npython3 {dashboard_script}\n")
            launcher.chmod(0o755)
            launch_in_terminal(launcher)
            break

        elif c == "3":
            break


# ////////////////////////////////////////////////////////#
#                 TOOLS  - tool functions                #
# ////////////////////////////////////////////////////////#

# Nmap
##############
def nmap_scan():
    os.system("clear")
    if not TARGET_IP or not ENG_PATH:
        input("No target set. Press Enter...")
        return

    scripts_dir = ENG_PATH / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    recon_dir = ENG_PATH / "recon_scans"
    recon_dir.mkdir(parents=True, exist_ok=True)

    # --- Scan Type ---
    while True:
        os.system("clear")
        print("Select Scan Type:\n")
        print("1) TCP")
        print("2) UDP")
        print("3) Both\n")
        scan = input("Select: ")
        if scan in ("1", "2", "3"):
            break
        input(f"{RED}Invalid selection. Press Enter...{RESET}")

    # --- Port Selection ---
    while True:
        os.system("clear")
        print("Port Selection:\n")
        print("1) Default nmap ports")
        print("2) Common ports (top 1000)")
        print("3) All ports (1-65535)")
        print("4) Port range")
        print("5) Specific port list\n")
        port_choice = input("Select: ")
        if port_choice in ("1", "2", "3", "4", "5"):
            break
        input(f"{RED}Invalid selection. Press Enter...{RESET}")

    port_flag = ""
    if port_choice == "2":
        port_flag = "--top-ports 1000"
    elif port_choice == "3":
        port_flag = "-p-"
    elif port_choice == "4":
        os.system("clear")
        port_range = input("Enter port range (e.g., 1-1000): ")
        port_flag  = f"-p {port_range}"
    elif port_choice == "5":
        os.system("clear")
        print("Enter ports separated by commas (e.g., 22,80,443)")
        port_list = input("Ports: ")
        if port_list.strip():
            port_flag = f"-p {port_list}"

    # --- Scripts ---
    while True:
        os.system("clear")
        print("Nmap Scripts:\n")
        print("1) Default")
        print("2) Vuln")
        print("3) Safe")
        print("4) Discovery")
        print("5) None\n")
        s = input("Select: ")
        if s in ("1", "2", "3", "4", "5"):
            break
        input(f"{RED}Invalid selection. Press Enter...{RESET}")

    script_map = {"1": "default", "2": "vuln", "3": "safe", "4": "discovery"}
    scripts    = f"--script {script_map[s]}" if s in script_map else ""

    # --- Version Scanning ---
    while True:
        os.system("clear")
        print("Version Scanning:\n")
        print("1) Yes")
        print("2) No\n")
        version_choice = input("Select: ")
        if version_choice in ("1", "2"):
            break
        input(f"{RED}Invalid selection. Press Enter...{RESET}")

    version_flag = "-sV" if version_choice == "1" else ""

    # --- Timing ---
    while True:
        os.system("clear")
        print("Scan Speed/Timing:\n")
        print("1) General scan (default, no flags)")
        print("2) T0 - Paranoid (very slow, IDS evasion)")
        print("3) T1 - Sneaky (slow, IDS evasion)")
        print("4) T2 - Polite (slower, less bandwidth)")
        print("5) T3 - Normal (default timing)")
        print("6) T4 - Aggressive (faster, assumes fast network)")
        print("7) T5 - Insane (very fast, may sacrifice accuracy)")
        print("8) Custom SYN stealth scan\n")
        style = input("Select: ")
        if style in ("1", "2", "3", "4", "5", "6", "7", "8"):
            break
        input(f"{RED}Invalid selection. Press Enter...{RESET}")

    stealth = ""
    timing  = ""

    if   style == "2": timing = "-T0"
    elif style == "3": timing = "-T1"
    elif style == "4": timing = "-T2"
    elif style == "5": timing = "-T3"
    elif style == "6": timing = "-T4"
    elif style == "7": timing = "-T5"
    elif style == "8":
        stealth = "-sS"
        while True:
            os.system("clear")
            print("Select timing for stealth scan:\n")
            print("1) T0 - Paranoid")
            print("2) T1 - Sneaky")
            print("3) T2 - Polite")
            print("4) Skip timing\n")
            t_choice = input("Select: ")
            if t_choice in ("1", "2", "3", "4"):
                break
            input(f"{RED}Invalid selection. Press Enter...{RESET}")
        if   t_choice == "1": timing = "-T0"
        elif t_choice == "2": timing = "-T1"
        elif t_choice == "3": timing = "-T2"

    date = datetime.now().strftime("%Y%m%d_%H%M%S")

    def build_and_launch(flag, label):
        outfile = recon_dir / f"NMAP_{TARGET_IP}_{label}_{date}"
        parts   = ["sudo nmap"]
        if flag:         parts.append(flag)
        if stealth:      parts.append(stealth)
        if timing:       parts.append(timing)
        if port_flag:    parts.append(port_flag)
        if scripts:      parts.append(scripts)
        if version_flag: parts.append(version_flag)
        parts.append(f"-oA {outfile}")
        parts.append(TARGET_IP)
        cmd = " ".join(parts)

        tmp_script = scripts_dir / f"nmap_{label}.py"
        tmp_script.write_text(f"""\
import os

RED   = "\\033[31m"
RESET = "\\033[0m"
BLUE  = "\\033[36m"

cmd = "{cmd}"
print(f"{{BLUE}}Running: {{cmd}}{{RESET}}\\n")
os.system(cmd)
input("\\nScan done. Press Enter...")
""")
        launcher = Path(f"/tmp/nmap_launch_{label}.sh")
        launcher.write_text(f"#!/bin/bash\npython3 {tmp_script}\n")
        launcher.chmod(0o755)
        launch_in_terminal(launcher)

    if scan == "1":
        build_and_launch("", "TCP")
    elif scan == "2":
        build_and_launch("-sU", "UDP")
    elif scan == "3":
        build_and_launch("", "TCP")
        time.sleep(0.5)
        build_and_launch("-sU", "UDP")


##############
# ffuf
##############
def ffuf_scan():
    os.system("clear")
    if not TARGET_IP or not ENG_PATH:
        input("No target set. Press Enter...")
        return

    scripts_dir = ENG_PATH / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)

    recon_dir = ENG_PATH / "recon_scans" / "web_recon_scans"
    recon_dir.mkdir(parents=True, exist_ok=True)

    WL_BASE = Path("/usr/share/wordlists/seclists")

    WORDLISTS = {
        "1": str(WL_BASE / "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt"),
        "2": str(WL_BASE / "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"),
        "3": str(WL_BASE / "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt"),
        "4": str(WL_BASE / "Discovery/Web-Content/common.txt"),
        "5": str(WL_BASE / "Discovery/Web-Content/Combined_Directories.txt"),
        "6": str(WL_BASE / "Discovery/Web-Content/WebRoot-IIS.txt"),
        "7": str(WL_BASE / "Discovery/Web-Content/Linux-dictionary.txt"),
    }

    COMMON_FLAGS = {
        "1": ("-fc 404",            "Filter out 404 responses"),
        "2": ("-fc 301,302",        "Filter out redirects"),
        "3": ("-mc 200",            "Only show 200 OK responses"),
        "4": ("-t 50",              "50 threads (faster)"),
        "5": ("-t 100",             "100 threads (aggressive)"),
        "6": ("-recursion",         "Recurse into found directories"),
        "7": ("-recursion-depth 2", "Recurse max 2 levels deep"),
        "8": ("-e .php,.html,.txt", "Fuzz with common web extensions"),
        "9": ("-e .asp,.aspx,.jsp", "Fuzz with Windows/Java extensions"),
    }

    # --- Wordlist ---
    while True:
        os.system("clear")
        print("Select a wordlist:\n")
        print("1) DirBuster-small")
        print("2) DirBuster-medium")
        print("3) DirBuster-large")
        print("4) common.txt")
        print("5) Combined_Directories.txt")
        print("6) WebRoot-windows")
        print("7) WebRoot-linux")
        print("8) Custom path\n")
        c = input("Select: ")
        if c == "8":
            custom = input("Enter full path to wordlist: ").strip()
            if not Path(custom).exists():
                input(f"{RED}File not found: {custom}. Press Enter...{RESET}")
                continue
            selected_wordlist = custom
            break
        elif c in WORDLISTS:
            selected_wordlist = WORDLISTS[c]
            if not Path(selected_wordlist).exists():
                input(f"{RED}Wordlist not found at {selected_wordlist}. Press Enter...{RESET}")
                continue
            break
        else:
            input(f"{RED}Invalid selection. Press Enter...{RESET}")

    # --- Protocol ---
    while True:
        os.system("clear")
        print("Type of Scan:\n")
        print("1) HTTP")
        print("2) HTTPS")
        print("3) Both (two windows)\n")
        http = input("Select: ")
        if http == "1":
            protocols = ["http://"]
            break
        elif http == "2":
            protocols = ["https://"]
            break
        elif http == "3":
            protocols = ["http://", "https://"]
            break
        else:
            input(f"{RED}Invalid selection. Press Enter...{RESET}")

    # --- Fuzz mode ---
    while True:
        os.system("clear")
        print("Fuzz mode:\n")
        print(f"1) Directory  ->  http://{TARGET_WEB}/FUZZ")
        print(f"2) Subdomain  ->  http://FUZZ.{TARGET_WEB}")
        print("3) Both\n")
        fuzz_mode = input("Select: ")
        target    = TARGET_WEB if TARGET_WEB else TARGET_IP
        if fuzz_mode == "1":
            fuzz_urls = [f"{p}{target}/FUZZ" for p in protocols]
            break
        elif fuzz_mode == "2":
            fuzz_urls = [f"{p}FUZZ.{target}" for p in protocols]
            break
        elif fuzz_mode == "3":
            fuzz_urls = [f"{p}{target}/FUZZ" for p in protocols] + \
                        [f"{p}FUZZ.{target}" for p in protocols]
            break
        else:
            input(f"{RED}Invalid selection. Press Enter...{RESET}")

    # --- Flags ---
    while True:
        os.system("clear")
        print("Common flags (enter numbers separated by spaces, or blank to skip):\n")
        for k, (flag, desc) in COMMON_FLAGS.items():
            print(f"{k}) {flag:<25} {desc}")
        print("\nExample: 1 4 8  adds  -fc 404 -t 50 -e .php,.html,.txt")
        print("Leave blank to skip\n")
        flag_input     = input("Select flags: ").strip()
        selected_flags = []
        if flag_input:
            choices = flag_input.split()
            invalid = [x for x in choices if x not in COMMON_FLAGS]
            if invalid:
                input(f"{RED}Invalid flag(s): {' '.join(invalid)}. Press Enter...{RESET}")
                continue
            selected_flags = [COMMON_FLAGS[x][0] for x in choices]
        break

    extra_flags  = " ".join(selected_flags)
    date         = datetime.now().strftime("%Y%m%d_%H%M%S")
    label        = Path(selected_wordlist).stem
    target_label = TARGET_WEB if TARGET_WEB else TARGET_IP

    # --- Build and launch ---
    if len(fuzz_urls) == 1:
        out_name   = f"{target_label}_ffuf_{label}_{date}.txt"
        outfile    = recon_dir / out_name
        cmd        = f"ffuf -w {selected_wordlist} -u {fuzz_urls[0]}{' ' + extra_flags if extra_flags else ''} -o {outfile}"
        tmp_script = scripts_dir / "ffuf_scan.py"
        tmp_script.write_text(f"""\
import os

RED   = "\\033[31m"
RESET = "\\033[0m"
BLUE  = "\\033[36m"

cmd = "{cmd}"
print(f"{{BLUE}}Running: {{cmd}}{{RESET}}\\n")
os.system(cmd)
input("\\nScan done. Press Enter...")
""")
        launcher = Path("/tmp/ffuf_launch.sh")
        launcher.write_text(f"#!/bin/bash\npython3 {tmp_script}\n")
        launcher.chmod(0o755)
        launch_in_terminal(launcher)
    else:
        for fuzz_url in fuzz_urls:
            proto_label = "http"  if "http://"  in fuzz_url else "https"
            fuzz_label  = "dir"   if "/FUZZ"    in fuzz_url else "sub"
            out_name    = f"{target_label}_ffuf_{proto_label}_{fuzz_label}_{label}_{date}.txt"
            outfile     = recon_dir / out_name
            cmd         = f"ffuf -w {selected_wordlist} -u {fuzz_url}{' ' + extra_flags if extra_flags else ''} -o {outfile}"
            tmp_script  = scripts_dir / f"ffuf_scan_{proto_label}_{fuzz_label}.py"
            tmp_script.write_text(f"""\
import os

RED   = "\\033[31m"
RESET = "\\033[0m"
BLUE  = "\\033[36m"

cmd = "{cmd}"
print(f"{{BLUE}}Running: {{cmd}}{{RESET}}\\n")
os.system(cmd)
input("\\nScan done. Press Enter...")
""")
            launcher = Path(f"/tmp/ffuf_launch_{proto_label}_{fuzz_label}.sh")
            launcher.write_text(f"#!/bin/bash\npython3 {tmp_script}\n")
            launcher.chmod(0o755)
            launch_in_terminal(launcher)
            time.sleep(0.5)


# ////////////////////////////////////////////////////////#
#                Network                                  #
# ////////////////////////////////////////////////////////#

NETWORK_TOOLS = [
    ("NMAP", nmap_scan),
    # add more here and the menu updates automatically
]

def network_tools():
    while True:
        os.system("clear")
        print("Select a tool:\n")
        for i, (name, _) in enumerate(NETWORK_TOOLS, 1):
            print(f"{i}) {name}")
        print(f"{len(NETWORK_TOOLS) + 1}) Back\n")

        c = input("Select: ")
        if not c.isdigit():
            continue
        c = int(c)
        if c == len(NETWORK_TOOLS) + 1:
            break
        elif 1 <= c <= len(NETWORK_TOOLS):
            NETWORK_TOOLS[c - 1][1]()
            break


# ////////////////////////////////////////////////////////#
#                WEB_ENUM                                 #
# ////////////////////////////////////////////////////////#

WEB_ENUM_TOOLS = [
    ("FFUF", ffuf_scan),
    # add more here and the menu updates automatically
]

def web_enum_tools():
    while True:
        os.system("clear")
        print("Select a tool:\n")
        for i, (name, _) in enumerate(WEB_ENUM_TOOLS, 1):
            print(f"{i}) {name}")
        print(f"{len(WEB_ENUM_TOOLS) + 1}) Back\n")

        c = input("Select: ")
        if not c.isdigit():
            continue
        c = int(c)
        if c == len(WEB_ENUM_TOOLS) + 1:
            break
        elif 1 <= c <= len(WEB_ENUM_TOOLS):
            WEB_ENUM_TOOLS[c - 1][1]()
            break


# ////////////////////////////////////////////////////////#
#                     MAIN MENU                          #
# ////////////////////////////////////////////////////////#

def main_menu():
    load_active()
    refresh_ips()

    while True:
        refresh_scan_status()
        os.system("clear")
        print_center(ASCII_ART)
        print_center(f"hAck'DHD  {RED}{LOCAL_IP}{RESET} | {RED}{PUBLIC_IP}{RESET}")
        print_center(f"DNS check does {RED}NOT{RESET} check if you are on your vpn!!!!! \n\n\n")
        print_line()
        print_line()
        print_line()
        print("\n\n\n\n")

        eng_active = bool(ENG_PATH)
        eng_name   = ENG_PATH.name if ENG_PATH else ""

        print(f"Engagement : {colorlogic(eng_name)}{eng_name}{RESET}")
        print(f"Target IP  : {colorlogic(TARGET_IP)}{TARGET_IP}{RESET}")
        print(f"Target Web : {colorlogic(TARGET_WEB)}{TARGET_WEB}{RESET}")
        print(f"In hosts file: {host_status()}")
        print(
            f"TCP[{checkmark(tcp_done, eng_active)}] | "
            f"TCP_FULL[{checkmark(tcp_full_done, eng_active)}] | "
            f"UDP_FAST[{checkmark(udp_fast_done, eng_active)}] | "
            f"UDP_FULL[{checkmark(udp_full_done, eng_active)}] | "
            f"TCP_BANNER[{checkmark(tcp_banner_done, eng_active)}] | "
            f"UDP_BANNER[{checkmark(udp_banner_done, eng_active)}] | "
            f"SNMP[{checkmark(snmp_done, eng_active)}]\n \n"
        )

        print("Start Here")
        print("========================")
        print("0) General Recon\n")
        print("1) Pre-Reqs")
        print("2) OSINT")
        print("3) Network")
        print("4) Web Enum")
        print("5) User PW Login")
        print("6) Exit\n")
        print("\nEngagement Options")
        print("========================")
        print("a) Choose engagement")
        print("b) Set target IP")
        print("c) Set target web")
        print("d) Add to host file")
        print("e) Remove from host file")
        print("f) Refresh menu and IPs")
        print("g) Move Engagement to Completed folder")
        print("h) Exit engagement\n")

        c = input("Select: ").lower()

        if   c == "1": prereqs()
        elif c == "2": pass
        elif c == "3": network_tools()
        elif c == "4": web_enum_tools()
        elif c == "5": pass
        elif c == "6": break
        elif c == "0": recon()
        elif c == "a": choose_engagement()
        elif c == "b": set_target_ip()
        elif c == "c": set_target_web()
        elif c == "d": add_host()
        elif c == "e": remove_host()
        elif c == "f": refresh_ips()
        elif c == "g": move_engagement()
        elif c == "h": exit_engagement()


# ////////////////////////////////////////////////////////#
#                                                        #
#                 DO NOT EDIT AFTER THIS                 #
#                      CLOSING                           #
#                                                        #
# ////////////////////////////////////////////////////////#

if __name__ == "__main__":
    main_menu()

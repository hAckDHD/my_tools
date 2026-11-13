#fancy vpn is used for managing the vpns you have saved in a file and validating if they are connected
#hackdhd
#03/17/26

################################
#          IMPORTS             #
################################
import os
import getpass
import shutil
import subprocess
import signal
import time
from pathlib import Path
import re


##########################################
# //////           COLOR           //////#
##########################################
RED    = "\033[31m"
GREEN  = "\033[32m"
RESET  = "\033[0m"
BLUE   = "\033[36m"
YELLOW = "\033[33m"

ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m')

def visible_len(text):
    return len(ANSI_ESCAPE.sub('', text))


##########################################
# //////       PRINT FUNCTIONS      //////
##########################################
def print_center(text):
    width = shutil.get_terminal_size().columns
    for line in text.split("\n"):
        print(line.center(width))

def printline(char="-"):
    width = shutil.get_terminal_size().columns
    print(char * width)


################################
#           ASCII ART          #
################################
ASCII_ART = r"""
                                                                     
                                                                     
██  ██ █████▄ ███  ██   ▄█████ ▄▄▄▄▄▄ ▄▄▄ ▄▄▄▄▄▄ ▄▄ ▄▄  ▄▄▄▄         
██▄▄██ ██▄▄█▀ ██ ▀▄██   ▀▀▀▄▄▄   ██  ██▀██  ██   ██ ██ ███▄▄         
 ▀██▀  ██     ██   ██   █████▀   ██  ██▀██  ██   ▀███▀ ▄▄██▀ ▄ ▄ ▄   
                                                                     
                                                                     
                                                                     
          ▄▄▄▄▄▄ ▄▄ ▄▄ ▄▄ ▄▄  ▄▄  ▄▄▄▄                               
            ██   ██▄██ ██ ███▄██ ██ ▄▄                               
            ██   ██ ██ ██ ██ ▀██ ▀███▀ ▄ ▄ ▄                         
                                                                     
"""


################################
#           USER INFO          #
################################
USER    = getpass.getuser()
VPN_DIR = Path(f"/home/{USER}/VPN")
PID_FILE = Path(f"/tmp/fancy_vpn.pid")


################################
#        MAKE VPN FOLDER       #
################################
def vpn_folder():
    VPN_DIR.mkdir(parents=True, exist_ok=True)
    for folder in ["HTB_ACADEMY", "HTB_LABS", "THM", "OTHER_VPN"]:
        (VPN_DIR / folder).mkdir(parents=True, exist_ok=True)


################################
#     VPN PROCESS DETECTION    #
################################
def get_running_openvpn_processes() -> list:
    """
    Scan ps aux for live openvpn processes.
    Returns sorted list of (config_path, pid) tuples.
    """
    found = []
    try:
        ps = subprocess.run(["ps", "aux"], capture_output=True, text=True)
        for line in ps.stdout.splitlines():
            if "openvpn" not in line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                pid = int(parts[1])
            except ValueError:
                continue
            cfg_path = None
            for i, part in enumerate(parts):
                if part == "--config" and i + 1 < len(parts):
                    cfg_path = parts[i + 1]
                    break
            if cfg_path:
                found.append((cfg_path, pid))
    except Exception:
        pass
    return sorted(found, key=lambda x: Path(x[0]).name.lower())


def get_connected_configs() -> set:
    """Return set of config path strings that have a live openvpn process."""
    return {cfg for cfg, _ in get_running_openvpn_processes()}


################################
#     PID FILE (bookkeeping)   #
################################
def load_pids() -> dict:
    pids = {}
    if PID_FILE.exists():
        for line in PID_FILE.read_text().splitlines():
            parts = line.strip().split("=", 1)
            if len(parts) == 2:
                path, pid = parts
                try:
                    pids[path] = int(pid)
                except ValueError:
                    pass
    return pids


def save_pids(pids: dict):
    PID_FILE.write_text("\n".join(f"{k}={v}" for k, v in pids.items()))


################################
#         VPN CHECK DISPLAY    #
################################
def vpn_check():
    term_width = shutil.get_terminal_size().columns
    GAP        = 3
    NUM_COLS   = 4
    col_width  = max(12, (term_width - GAP * (NUM_COLS - 1)) // NUM_COLS)
    short      = col_width < 36  # compact badges on narrow terminals

    connected = get_connected_configs()

    dirs = [
        ("HTB ACADEMY", VPN_DIR / "HTB_ACADEMY"),
        ("HTB LABS",    VPN_DIR / "HTB_LABS"),
        ("THM",         VPN_DIR / "THM"),
        ("OTHER",       VPN_DIR / "OTHER_VPN"),
    ]

    def build_col(directory, connected):
        try:
            files = sorted([f for f in directory.iterdir() if f.is_file()], key=lambda f: f.name.lower())
        except Exception:
            files = []
        if not files:
            return [f"{RED}[NO FILES]{RESET}"]
        rows = []
        for idx, f in enumerate(files, 1):
            if str(f) in connected:
                badge, badge_len = (f"{GREEN}[C]{RESET}", 3) if short else (f"{GREEN}[Connected]{RESET}", 11)
            else:
                badge, badge_len = (f"{RED}[X]{RESET}", 3) if short else (f"{RED}[Disconnected]{RESET}", 14)
            prefix   = f"{idx}) "
            max_name = col_width - len(prefix) - 1 - badge_len
            name     = f.name
            if max_name > 1 and len(name) > max_name:
                name = name[:max_name - 1] + "…"
            rows.append(f"{prefix}{name} {badge}")
        return rows

    headers   = [h for h, _ in dirs]
    cols_data = [build_col(d, connected) for _, d in dirs]

    max_rows = max(len(c) for c in cols_data)
    for c in cols_data:
        while len(c) < max_rows:
            c.append("")

    # Header
    line = ""
    for i, h in enumerate(headers):
        cell = h[:col_width]
        line += f"{BLUE}{cell}{RESET}" + " " * (col_width - len(cell))
        if i < NUM_COLS - 1:
            line += " " * GAP
    print(line)

    # Divider
    print(("─" * col_width + " " * GAP) * (NUM_COLS - 1) + "─" * col_width)

    # Rows
    for row_idx in range(max_rows):
        line = ""
        for j, col in enumerate(cols_data):
            cell = col[row_idx]
            line += cell + " " * max(0, col_width - visible_len(cell))
            if j < NUM_COLS - 1:
                line += " " * GAP
        print(line)


################################
#        CONNECT VPN           #
################################
def pick_folder():
    folders = ["HTB_ACADEMY", "HTB_LABS", "THM", "OTHER_VPN"]
    print("\nSelect folder:")
    for i, name in enumerate(folders, 1):
        print(f"  {i}) {name}")
    print("  0) Cancel")

    while True:
        c = input("Folder: ").strip()
        if c == "0":
            return None
        try:
            idx = int(c) - 1
            if 0 <= idx < len(folders):
                return VPN_DIR / folders[idx]
        except ValueError:
            pass
        print("Invalid choice.")


def pick_file_from_folder(folder: Path):
    files = sorted([f for f in folder.iterdir() if f.is_file()], key=lambda f: f.name.lower())
    if not files:
        print(f"{RED}No VPN files found in {folder.name}.{RESET}")
        input("Press Enter to continue...")
        return None

    print(f"\nFiles in {folder.name}:")
    for i, f in enumerate(files, 1):
        print(f"  {i}) {f.name}")
    print("  0) Cancel")

    while True:
        c = input("Select file: ").strip()
        if c == "0":
            return None
        try:
            idx = int(c) - 1
            if 0 <= idx < len(files):
                return files[idx]
        except ValueError:
            pass
        print("Invalid choice.")


def log_path(config: Path) -> str:
    return f"/tmp/fancy_vpn_{config.stem}.log"


def read_log(config: Path) -> str:
    """Log is root-owned (openvpn runs as root), so read it via sudo."""
    r = subprocess.run(["sudo", "cat", log_path(config)], capture_output=True, text=True)
    return r.stdout


def wait_for_connection(config: Path, timeout: int = 20):
    """
    Poll the log until OpenVPN reports success, or the process dies / times out.
    Returns (pid or None, status) where status is 'ok', 'dead', or 'timeout'.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(1)
        pid = next((p for cfg, p in get_running_openvpn_processes() if cfg == str(config)), None)
        log = read_log(config)
        if "Initialization Sequence Completed" in log:
            return pid, "ok"
        if pid is None and log:
            return None, "dead"
    pid = next((p for cfg, p in get_running_openvpn_processes() if cfg == str(config)), None)
    return pid, "timeout"


def connect_vpn():
    folder = pick_folder()
    if folder is None:
        return

    config = pick_file_from_folder(folder)
    if config is None:
        return

    connected = get_connected_configs()
    if str(config) in connected:
        print(f"\n{YELLOW}Already connected to {config.name}.{RESET}")
        input("Press Enter to continue...")
        return

    # Authenticate sudo up front so the password prompt is explicit
    print(f"\n{BLUE}sudo is required to start OpenVPN.{RESET}")
    try:
        if subprocess.run(["sudo", "-v"]).returncode != 0:
            print(f"{RED}sudo authentication failed.{RESET}")
            input("Press Enter to continue...")
            return
    except FileNotFoundError:
        print(f"{RED}sudo not found.{RESET}")
        input("Press Enter to continue...")
        return

    print(f"{BLUE}Launching OpenVPN for {config.name}...{RESET}")

    # NOTE: no --route-nopull. HTB/THM configs don't push a default route, so they
    # are already split-tunnel; --route-nopull would drop the lab routes they push.
    cmd = [
        "sudo", "openvpn",
        "--config", str(config),
        "--daemon",
        "--log", log_path(config),
    ]

    try:
        # Clear the old log so we don't read a previous run's output
        subprocess.run(["sudo", "rm", "-f", log_path(config)])

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"{RED}Failed to start OpenVPN:{RESET}\n{result.stderr}{result.stdout}")
            input("Press Enter to continue...")
            return

        print(f"{BLUE}Waiting for tunnel to come up...{RESET}")
        pid, status = wait_for_connection(config)

        if status == "ok":
            if pid:
                pids = load_pids()
                pids[str(config)] = pid
                save_pids(pids)
            print(f"{GREEN}Connected! PID {pid} — running in background.{RESET}")
        else:
            if status == "dead":
                print(f"{RED}OpenVPN exited. Last log lines:{RESET}")
            else:
                print(f"{YELLOW}Tunnel not up after 20s (PID {pid}). Last log lines:{RESET}")
            print("\n".join(read_log(config).splitlines()[-20:]))
            print(f"{YELLOW}Full log: sudo cat {log_path(config)}{RESET}")

    except FileNotFoundError:
        print(f"{RED}openvpn not found. Install it with: sudo apt install openvpn{RESET}")

    input("Press Enter to continue...")


################################
#       DISCONNECT VPN         #
################################
def disconnect_vpn():
    running = get_running_openvpn_processes()

    if not running:
        print(f"\n{YELLOW}No active VPN connections found.{RESET}")
        input("Press Enter to continue...")
        return

    print("\nActive connections:")
    for i, (cfg, pid) in enumerate(running, 1):
        print(f"  {i}) {Path(cfg).name}  {GREEN}[Connected]{RESET}  (PID {pid})")
    print("  0) Cancel")

    while True:
        c = input("Disconnect which: ").strip()
        if c == "0":
            return
        try:
            idx = int(c) - 1
            if 0 <= idx < len(running):
                cfg, pid = running[idx]
                break
        except ValueError:
            pass
        print("Invalid choice.")

    print(f"\n{BLUE}Stopping OpenVPN (PID {pid})...{RESET}")
    try:
        subprocess.run(["sudo", "kill", str(pid)], check=True)
        time.sleep(1)
        pids = load_pids()
        pids.pop(cfg, None)
        save_pids(pids)
        print(f"{GREEN}Disconnected successfully.{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}Failed to kill process: {e}{RESET}")

    input("Press Enter to continue...")


################################
#            MAIN MENU         #
################################
def main_menu():
    vpn_folder()
    while True:
        os.system("clear")
        print_center(ASCII_ART)
        print("\n\n\n")
        printline()
        printline()
        printline()
        print("\n\n\n")
        print(f"{BLUE}VPN Status{RESET}")
        printline()
        vpn_check()
        print("\n\n\n")

        print("OPTIONS:")
        print("1) CONNECT VPN")
        print("2) DISCONNECT VPN")
        print("3) REFRESH STATUS")
        print("4) EXIT")
        print("\n\n\n")

        c = input("Select: ").strip()

        if   c == "1": connect_vpn()
        elif c == "2": disconnect_vpn()
        elif c == "3": continue
        elif c == "4": break


################################
#         DO NOT EDIT          #
################################
if __name__ == "__main__":
    main_menu()

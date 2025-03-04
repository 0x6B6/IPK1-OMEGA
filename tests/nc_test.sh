#!/bin/bash
POSIXLY_CORRECT=yes

#Author: Marek Pazúr
#Login: xpazurm00
#Date: 04.03.2025

#Variables
IF="lo"
TARGET="localhost"
PORTS="12346,12347,12348,7777"
TEST_DIR="nc_test_result"

mkdir -p "$TEST_DIR"

scan_hosts() {
  sudo ../ipk-l4-scan -i $IF $TARGET -t $PORTS > "$TEST_DIR"/ipk.txt
  sudo nmap -e $IF $TARGET -sS -p $PORTS > "$TEST_DIR"/ref.txt

  ipk_result=$(parse_results "$TEST_DIR"/ipk.txt)
  ref_result=$(parse_results "$TEST_DIR"/ref.txt)

  compare_results "$ipk_result" "$ref_result"
}

parse_results() {
  output=$(grep -Eo '([0-9]+/tcp\s+[a-z]+)' "$1" | awk '{print $1, $2}' | sort)
  echo "$output"
  echo "$output" > "$1".log
}

compare_results() {
  echo "IPK scan compared to Nmap for localhost"

  diff_result=$(diff <(echo "$1") <(echo "$2"))

  if [ -z "$diff_result" ]; then
    echo -e "No difference between ipk-l4-scan and nmap\n"
    cat "$TEST_DIR"/ipk.txt.log
  else
    echo -e "Difference(s) found:\n"
    echo -e "$diff_result\n\n"
    cat "$TEST_DIR"/*.txt.log
  fi
}

echo -e "Scanning ports $PORTS on localhost before opening them with netcat\n"

scan_hosts

nc -l -p 12346 &
nc -l -p 12347 &
nc -l -p 12348 &
echo -e "\nNow listening on ports $PORTS"

echo "Scanning ports $PORTS on localhost with netcat activated\n"
scan_hosts

killall nc
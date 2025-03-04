#!/bin/bash
POSIXLY_CORRECT=yes

#Author: Marek Pazúr
#Login: xpazurm00
#Date: 04.03.2025

#Variables
IF="ens33"
TARGET=("www.vutbr.cz" "1.1.1.1" "www.scanme.org" "8.8.8.8")
UDP="53,161,123"
TEST_DIR="udp_test_result"

mkdir -p "$TEST_DIR"

scan_hosts() {
  for host in "${TARGET[@]}"; do

    sudo ../ipk-l4-scan -i $IF $host -u $UDP -w 1000 > "$TEST_DIR"/ipk_$host.txt
    sudo nmap -e $IF $host -sU -p $UDP > "$TEST_DIR"/ref_$host.txt

    ipk_result=$(parse_results "$TEST_DIR"/ipk_$host.txt)
    ref_result=$(parse_results "$TEST_DIR"/ref_$host.txt)

    compare_results "$ipk_result" "$ref_result" "$host"
  done
}

parse_results() {
  output=$(grep -Eo '([0-9]+/udp\s+[a-z]+)' "$1" | awk '{print $1, $2}' | sort)
  echo "$output"
  echo "$output" > "$1".log
}

compare_results() {
  echo "IPK scan compared to Nmap for host $3"

  diff_result=$(diff <(echo "$1") <(echo "$2"))

  if [ -z "$diff_result" ]; then
    echo "No difference between ipk-l4-scan and nmap"
  else
    echo "Difference(s) found:"
    echo "$diff_result"
  fi
}

echo "Basic UDP test, this may take a while..."

scan_hosts
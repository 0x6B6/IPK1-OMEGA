#!/bin/bash
POSIXLY_CORRECT=yes

#Author: Marek Pazúr
#Login: xpazurm00
#Date: 04.03.2025

#Variables
IF="enp0s3"
TARGET=("www.vutbr.cz" "1.1.1.1" "www.scanme.org" "8.8.8.8")
TCP="21,22,53,80,443,110,143,3389"
TEST_DIR="tcp_test_result"

mkdir -p "$TEST_DIR"

scan_hosts() {
  for host in "${TARGET[@]}"; do

    sudo ../ipk-l4-scan -w 1500 -i $IF $host -t $TCP > "$TEST_DIR"/ipk_$host.txt
    sudo nmap -e $IF $host -sS -p $TCP > "$TEST_DIR"/ref_$host.txt

    ipk_result=$(parse_results "$TEST_DIR"/ipk_$host.txt)
    ref_result=$(parse_results "$TEST_DIR"/ref_$host.txt)

    compare_results "$ipk_result" "$ref_result" "$host"
  done
}

parse_results() {
  output=$(grep -Eo '([0-9]+/tcp\s+[a-z]+)' "$1" | awk '{print $1, $2}' | sort | uniq)
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

echo "Basic IPv4 & IPv6 TCP test, this may take a while..."

scan_hosts
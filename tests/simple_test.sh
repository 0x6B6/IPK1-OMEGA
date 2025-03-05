#!/bin/bash
POSIXLY_CORRECT=yes

#Author: Marek Pazúr
#Login: xpazurm00
#Date: 04.03.2025

#Variables
TEST_DIR="simple_test"
PROGRAM="ipk-l4-scan"

sudo ../"$PROGRAM" -i "ens33" "www.scanme.org" -t "22,25,53,70,80,113,443" -w 1500

sudo ../"$PROGRAM" -i "ens33" "www.scanme.org" -u "21,53,67,111" -w 1500

sudo ../"$PROGRAM" -i "lo" "localhost" -t "10000 to 10010" -u "10020 to 10030"

nc -l -p 10005 &
nc -l -u -p 10025 -k &

sudo ../"$PROGRAM" -i "lo" "localhost" -t "10000 to 10010" -u "10020 to 10030"

killall nc
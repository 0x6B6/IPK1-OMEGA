#!/bin/bash
POSIXLY_CORRECT=yes

#Author: Marek Pazúr
#Login: xpazurm00
#Date: 04.03.2025

#Variables
IF="lo"
TARGET="localhost"
PORTS="80,443"
TEST_DIR="memory_result"
PROGRAM="ipk-l4-scan"

mkdir -p "$TEST_DIR"

echo "Initiating memory test, this may take a while..."

#Scan memtest
sudo valgrind ../"$PROGRAM" -i "$IF TARGET" -t "$PORTS" > /dev/null 2> "$TEST_DIR"/memtest1.txt

#Interface print memtest
sudo valgrind ../"$PROGRAM" > /dev/null 2> "$TEST_DIR"/memtest2.txt

#Error memtest
sudo valgrind ../"$PROGRAM" -i wrong > /dev/null 2> "$TEST_DIR"/memtest3.txt

if grep -iE "(definitely lost|indirectly lost|possibly lost|invalid)" "$TEST_DIR"/memtest*.txt; then
	echo "Memory leaks detected"
else
	echo "No memory issues detected"
fi
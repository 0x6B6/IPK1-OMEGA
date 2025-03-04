#!/bin/bash
POSIXLY_CORRECT=yes

#Author: Marek Pazúr
#Login: xpazurm00
#Date: 04.03.2025

#Variables
PROG="./ipk-l4-scan"
SUFFIX="-t 80 -u 53"
PREFIX="-i lo localhost"

#Test cases, the last number is expected return code
declare -a TESTCASES=(
	"-i --interface 1"
	"-i -i 1"
	"-i localhost $SUFFIX 1"
	"-i interface $SUFFIX 1"
	"$PREFIX -t 80 -pt 443 1"
	"$PREFIX -t 0 1"
	"$PREFIX -t 65536 1"
	"$PREFIX -t 0-65536 1"
	"$PREFIX -u 53 --pu 54 1"
	"$PREFIX -u 0-65536 1"
	"$PREFIX -t 1- 1"
	"$PREFIX -t -50 1"
	"$PREFIX -t 80-443- -u 55 1"
	"--pt 80 --pu 53 1"
	"$PREFIX -t 0-53 1"
	"$PREFIX -t 65534-65536 1"
	"$PREFIX 1"

	"$PREFIX -t 80 0"
	"$PREFIX -t 80to81 0"
	"$PREFIX -t 80 -u 53 -l 0 0"
	"$PREFIX --pt 80 --pu 53 -l 0 0"
	"$PREFIX -t 80 -u 53 --ratelimit 0 0"
	"$PREFIX --pt 80 --pu 53 --ratelimit 0 0"
	"$PREFIX $SUFFIX -v 0"
	"$PREFIX $SUFFIX --verbose 0"
	"$PREFIX $SUFFIX -v 0"
	"$PREFIX $SUFFIX -v -l 0 0"
	"$PREFIX -t 1,2,3 0"
	"$PREFIX -t 65534to 0"
	"$PREFIX -t to3 0"
	"$PREFIX -t 1-3 -u to2 0"
)

opts_parse_test() {

	for test in "${TESTCASES[@]}"; do
		params=$(echo $test | sed 's/ [^ ]*$//')
		
		expected_code=$(echo $test | awk '{print $NF}')

		sudo ../ipk-l4-scan -w 10 -r 0 $params > /dev/null 2>&1

		return_code=$?

		if [ "$return_code" -ne "$expected_code" ]; then
			echo -e "\e[31m[FAIL]\e[0m: '$PROG $params' with return code $return_code (expected code $expected_code)"
		else
			echo -e "\e[32m[PASS]\e[0m: '$PROG $params' with expected return code $return_code"
		fi
	done
}

opts_parse_test
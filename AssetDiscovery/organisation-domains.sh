#!/bin/bash

# Check command line argument number
if [ "$#" -ne 1  ]; then
	echo "[!] Usage: $0 <organisation name or domain>"
	exit 1
fi

# If domain name:
if [[ "$1" == *.* ]]; then
	curl -s "https://crt.sh/?q=$1&output=json" >> $1-raw.json
# If organisation name:
else
	curl -s "https://crt.sh/?o=$1&output=json" >> $1-raw.json
fi

# Sort data
cat $1-raw.json | jq -r '.[].common_name' | sed 's/\*//g' | sort -u >> $1-domains.txt

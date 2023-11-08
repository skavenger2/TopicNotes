#!/bin/bash

# Check command line argument number
if [ "$#" -ne 1  ]; then
        echo "[!] Usage: $0 <domain>"
        exit 1
fi

whois $1 | grep Registrant

# Find All Domains From The Organization Name

Get domains from <https://crt.sh> and output to a file  
`curl -s https://crt.sh/\?o\=PayPal\&output\=json >> PayPal.txt`

Sort the json data to get domains and subdomains  
`cat PayPal.txt | jq -r '.[].common_name' | sed 's/\*//g' | sort -u`

Only top level domains (<https://github.com/Cgboal/DomainParser>)  
`cat PayPal.txt | jq -r '.[].common_name' | sed 's/\*//g' | sort -u | domainparser | sort -u`

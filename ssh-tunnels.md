
# SSH Tunnelling

## For Multiple Hosts

```bash
# from local terminal to first host:  
ssh -L 1080:127.0.0.1:1081  

# from first host to second host:  
ssh -L 1081:127.0.0.1:1082  

# from second host to third host:  
ssh -D 1082  

# this will let you forward traffic to 127.0.0.1:1080 on your local terminal and have it exit on to the internet from host 3  
```

## For a Single Host

```bash
ssh -D 1080 root@<ip>
```

## For proxying Traffic

```bash
sudo vim /etc/proxychains4.conf

# Enable Quiet Mode (Recommended): 
# Uncomment (#quiet_mode)
quiet_mode

# Set tunnelled port
socks4  127.0.0.1  1080

# Back on the command line
proxychains4 nmap -sV -Pn -n -iL targets.txt -oA results
```


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
ssh -D 1080 root@<ip>   # add -N to not execute command (not necessary)
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

## RDP Over a Double SSH Tunnel

Linux machine -> jump box -> attack server -> rdp machine  

Create a port forward from the jump box to rdp machine via the attack server:  

`ssh -L 1234:<rdp machine ip>:3389 user@attack-server` - change `1234` to any unused port on the jump box, port `3389` on the rdp machine for rdp  

Create a port forward from the linux machine to the jump box, using the port in the previous command:  

`ssh -L 5678:localhost:1234 root@<jump box>` - `5678` can be changed to any unused port on the local machine  

Then RDP to locahost:  

`xfreerdp /u:<user> /p:<password> /v:localhost:5678`

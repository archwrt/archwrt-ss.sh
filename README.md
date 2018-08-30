## DEPENDS
* shadowsocks-libev
* ipset
* iptables
* dnsutils
* dnsproxy
* haveged
```
sudo pacman -S shadowsocks-libev ipset iptables dnsutils haveged
aurman -S dnsproxy
```

## INSTALLATION
>Only tested on Arch Linux
```
git clone https://github.com/monlor/Arch-Router-SS
mkdir -p /opt/archss
cp -rf ./Arch-Router-SS/archss.sh /opt/archss/
cp -rf ./Arch-Router-SS/archss.service /lib/systemd/system
chmod +x /opt/archss/archss.sh
/opt/archss/archss.sh # getting start
```

## Auto Run
### Netctl hooks for wan start
```
cat> /etc/netctl/hooks/archss <<EOF
#!/bin/sh
ExecUpPost="systemctl start archss"
ExecDownPre="systemctl stop archss"
EOF
chmod +x /etc/netctl/hooks/archss
```
### Auto run after reboot
```
systemctl enable archss
```
## USED FOR
Bypassing the Great Firewall of China by setting up a transparent proxy, using Shadowsocks-libev and iptables.
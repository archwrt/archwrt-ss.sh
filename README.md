##DEPENDS
* shadowsocks-libev
* ipset
* iptables
* dnsutils
* dnsproxy
* haveged
```
sudo pacman -S shadowsocks-libev ipset iptables dnsutils haveged
sudo aurman -S dnsproxy
```

##INSTALLATION
>Only Test in Arch Linux
```
git clone https://github.com/monlor/Arch-Router-SS
mkdir -p /opt/archss
cp -rf ./Arch-Router-SS/archss.sh /opt/archss/
cp -rf ./Arch-Router-SS/archss.service /lib/systemd/system
chmod +x /opt/archss/archss.sh
/opt/archss/archss.sh # getting start
```

##WHAT DOES IT DO
CROSS THE CHINESE FIREWALL
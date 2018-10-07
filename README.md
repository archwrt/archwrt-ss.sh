## DEPENDENCE

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
curl -skLo /tmp/archss.sh https://github.com/monlor/Arch-Router-SS/raw/master/archss.sh
chmod +x /tmp/archss.sh
/tmp/archss.sh install
```

## UNINSTALLATION

```
sudo rm -rf /opt/archss
sudo rm /lib/systemd/system/archss.service
```

## AUTO RUN

### Netctl hooks for wan start

```
cat> /etc/netctl/hooks/archss <<EOF
#!/bin/sh
ExecUpPost="systemctl start archss"
ExecDownPre="systemctl stop archss"
EOF
chmod +x /etc/netctl/hooks/archss
```

### Auto run at startup

```
systemctl enable archss
```

## USED FOR

Bypassing the Great Firewall of China by setting up a transparent proxy, using [Shadowsocks-libev](https://github.com/shadowsocks/shadowsocks-libev) and iptables.

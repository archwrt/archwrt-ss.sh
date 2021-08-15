archwrt-ss.sh
---

A simple Shadowsocks transparent proxy setup script.

## Main features

* GFWList Mode supported
* Chnroute (Bypass Mainland IP) Mode supported
* Customized Blacklist/Whitelist supported
* Game Mode (udp redirection on both OUTPUT chains and PREROUTING chains ) supported

## Depends

* shadowsocks-rust or v2ray-core
* simple-obfs (optional)
* shadowsocks-v2ray-plugin (optional)
* dnsmasq
* ipset
* iptables
* [AdguardTeam/dnsproxy](https://github.com/AdguardTeam/dnsproxy) (optional)



## Usage

```
Info:
  Contibuted by monlor & edward-p
Usage:
  archwrt-ss.sh {Command} {Option} {Config File}
Commands:
  start | stop | restart | status | update
Options:
  gfwlist | bypass | gamemode | global
Config File:
  Specify which config.json to use. by default the script will use the last one used.
Example:
  archwrt-ss.sh start bypass          Start with bypass mode
  archwrt-ss.sh restart gfwlist       Restart with gfwlist mode
  archwrt-ss.sh restart bypass sfo2   Retart with bypass mode using /etc/shadowsocks/sfo2.json
  archwrt-ss.sh restart sfo2          Retart using /etc/shadowsocks/sfo2.json
  archwrt-ss.sh start                 Start with default mode [current:bypass]
  archwrt-ss.sh update                Update rules

```

## Installation

Install on AUR (Archlinux only)

```
yay -S archwrt-ss.sh-git
```

Install manually

```
$ git clone https://github.com/archwrt/archwrt-ss.sh
$ cd archwrt-ss.sh
$ sudo install -Dm755 archwrt-ss.sh /usr/bin/archwrt-ss.sh
$ sudo install -Dm644 archwrt-ss.conf /etc/archwrt/ss/archwrt-ss.conf
$ sudo install -Dm644 archwrt-ss.service /usr/lib/systemd/system/archwrt-ss.service
$ sudo systemctl daemon-reload
```

## Start

The script use `systemctl start shadowsocks-libev-redir@${ss_conf}` to start ss-redir.

You need set up your config name (without extension `.json`) to `ss_conf` in `/etc/archwrt/ss/archwrt-ss.conf`

You need write your `${ss_conf}.json` in `/etc/shadowsocks`

Check if there's any error, for example:

```
$ ss-redir -c /etc/shadowsocks/config.json
```

Not yet, you need set `puredns_port` in `/etc/archwrt/ss/archwrt-ss.conf` as the upstream of the dnsmasq.

Now you can start by:

```
$ sudo systemctl start archwrt-ss.service
```

For auto start:

```
systemctl enable archwrt-ss.service
```

## Customized Blacklist/Whitelist

- blacklist: by default, located at `/etc/archwrt/ss/blacklist.txt` 
- whitelist: by default, located at `/etc/archwrt/ss/whitelist.txt` 

comment with `#` is supported

IP/NET/Domains suported, one line each, for example:

```
...
# This is a comment
127.0.0.1 #ip
127.0.0.0/24 #net
example.com #domain
...
```

## FAQ
### `/etc/resolv.conf` is overwrite by NetworkManager
Solution:

create a file like `/etc/NetworkManager/conf.d/10-dns.conf` with following c:

``` ini
[global-dns-domain-*]
servers=::1,127.0.0.1
```

archwrt-ss.sh
---

A simple Shadowsocks transparent proxy setup script.

## Main features

* GFWList Mode supported
* Chnroute (Bypass Mainland IP) Mode supported
* Customized Blacklist/Whitelist supported
* Game Mode (udp redirection on both OUTPUT chains and PREROUTING chains ) supported

## Depends

* shadowsocks-libev
* simple-obfs (optional)
* shadowsocks-v2ray-plugin (optional)
* dnsmasq
* ipset
* iptables
* bind-tools
* [AdguardTeam/dnsproxy](https://github.com/AdguardTeam/dnsproxy) (optional) - [PKGBUILD](https://github.com/archwrt/repo/tree/master/archwrt/dnsproxy)



## Usage

```
$ archwrt-ss.sh --help
Info:
  Contibuted by monlor & edward-p
Usage:
  archwrt-ss.sh {Command} {Option} {Config File}
Commands:
  start | stop | restart | status | config | update
Options:
  gfwlist | bypass | gamemode | global
Config File:
  Specify which config.json to use. by default the script will use the last one used.
Example:
  archwrt-ss.sh start bypass          Start with bypass mode
  archwrt-ss.sh restart gfwlist       Restart with gfwlist mode
  archwrt-ss.sh restart bypass sfo2   Retart with bypass mode using /opt/archwrt-ss/sfo2.json
  archwrt-ss.sh restart sfo2          Retart using /opt/archwrt-ss/sfo2.json
  archwrt-ss.sh start                 Start with default mode [current:gfwlist]
  archwrt-ss.sh config                Generate a config.json to /opt/archwrt-ss/config.json
  archwrt-ss.sh config nyc1           Generate a config.json to /opt/archwrt-ss/nyc1.json
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
$ sudo install -Dm644 archwrt-ss.conf /opt/archwrt-ss/archwrt-ss.conf
$ sudo install -Dm644 archwrt-ss.service /usr/lib/systemd/system/archwrt-ss.service
$ sudo systemctl daemon-reload
```

## Start

Before using `systemctl start archwrt-ss.service`, you need a valid `config.json` for shadowsocks, the following command will start a wizzard for that.

```
$ sudo archwrt-ss.sh config
```

When it is done, your `config.json` will be located at `/opt/archwrt-ss/config.json`.

It is recommend to check if there's any error in your `config.json` by running:

```
$ ss-redir -c /opt/archwrt-ss/config.json
```

Not yet, you may want to have a look on `/opt/archwrt-ss/archwrt-ss.conf`. Change some configs if you like.

Now you can start by

```
$ sudo systemctl start archwrt-ss.service
```

For auto start

```
systemctl enable archwrt-ss.service
```

## Customized Blacklist/Whitelist

- blacklist: by default, located at `/opt/archwrt-ss/blacklist.txt` 
- whitelist: by default, located at `/opt/archwrt-ss/whitelist.txt` 

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

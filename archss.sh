#!/bin/sh
#copyright by monlor

ss_path="/opt/archss"
if [ ! -f "$ss_path/config" ]; then
	echo "Installing default config to $ss_path/config"
	CONFIG=$(mktemp)
	cat > $CONFIG << EOF
# Custom Settings
ss_mode="gfwlist" # default
local_port="1080"
fast_open="true"

# DNS
modify_resolv=true #using mount --bind to safely overwrite /etc/resolv.conf to use 127.0.0.1
dns_port="5353"
remote_dns_ip="8.8.8.8"
remote_dns_port="53"
ss_cdn="202.141.162.123" # for not gfwlist mode, DNS Server 202.141.162.123 is hosed by USTC LUG
ss_cdn_port="5353" # use 5353 instead of 53 to protect from being attack
lanip="" # set it for chromecast

# File Path
ss_redir="/usr/bin/ss-redir"
dnsproxy="/usr/bin/dnsproxy"
config_path="\$ss_path/config.json"
gfwlist_path="\$ss_path/gfwlist.conf"
chnroute_path="\$ss_path/chnroute.txt"
cdn_path="\$ss_path/cdn.txt"
white_path="\$ss_path/whitelist.txt" # add custom white list, support ip or domain
black_path="\$ss_path/blacklist.txt" # add custom white list, support ip or domain
EOF
	install -D -m644 $CONFIG $ss_path/config
	rm $CONFIG
fi

source $ss_path/config

help() {

	cat << EOF
Info:
	Copyright by monlor
Usage:
	$0 {Command} {Option}
Commands:
	start|stop|restart|status|config|update|install
Options:
	gfwlist|bypass|gamemode|whole
	rules|script
Example:
	$0 start bypass	Start with bypass mode
	$0 restart gfwlist	Restart with gfwlist mode
	$0 start		Start with default mode[$ss_mode]
	$0 config		Modify server config
	$0 update rules	Update rules
	$0 install		Install scipts to /opt/archss
EOF

}

install_scripts() {
	[ ! -d "$ss_path" ] && mkdir -p "$ss_path"
	[ ! -f "$white_path" ] && touch "$white_path"
	[ ! -f "$black_path" ] && touch "$black_path"

	echo "Installing archss.sh to $ss_path/archss.sh"
	install -D -m755 $0 "$ss_path/archss.sh"

	echo "Installing archss.service to /lib/systemd/system/archss.service"
	SERVICE=$(mktemp)
	cat > $SERVICE << EOF
[Unit]
Description=ss/ssr/socks5 global proxy script
ConditionFileIsExecutable=/opt/archss/archss.sh
ConditionFileNotEmpty=/opt/archss/config.json
Requires=network.target network-online.target
After=network.target network-online.target haveged.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/archss/archss.sh start
ExecStop=/opt/archss/archss.sh stop
ExecReload=/opt/archss/archss.sh restart

[Install]
WantedBy=multi-user.target
EOF
	install -D -m644 $SERVICE /lib/systemd/system/archss.service
	rm $SERVICE

	echo "Updating Rules..."
	update
}

prepare() {

	[ ! -d "$ss_path" ] && mkdir -p "$ss_path"
	[ ! -f "$white_path" ] && touch "$white_path"
	[ ! -f "$black_path" ] && touch "$black_path"
	[ ! -d /etc/dnsmasq.d ] && mkdir -p /etc/dnsmasq.d
	[ -z "$(cat /etc/dnsmasq.conf | grep "^conf-dir")" ] && echo "conf-dir=/etc/dnsmasq.d/,*.conf" >> /etc/dnsmasq.conf
	[ "$(cat /proc/sys/net/ipv4/ip_forward)" != '1' ] && echo 1 > /proc/sys/net/ipv4/ip_forward
	# deal ss mode
	if [ -z "$1" ]; then
		[ -f "$ss_path"/ssmode.txt ] && ss_mode="$(cat "$ss_path"/ssmode.txt)"
	else
		ss_mode="$1"
		echo -n "$ss_mode" > "$ss_path"/ssmode.txt
	fi

}

env_check() {

	echo "环境检查中..."
	[ "$(whoami)" != "root" ] && echo "请使用root用户运行！" && exit 1
	!(hash ss-redir &> /dev/null) && echo "请安装ss-redir程序[pacman -S shadowsocks-libev]！" && exit 1
	!(hash curl &> /dev/null) && echo "请安装curl程序[pacman -S curl]！" && exit 1
	!(hash ipset &> /dev/null) && echo "请安装ipset程序[pacman -S ipset]！" && exit 1
	!(hash iptables &> /dev/null) && echo "请安装iptables程序[pacman -S iptables]！" && exit 1
	!(hash dig &> /dev/null) && echo "请安装dig程序[pacman -S dnsutils]！" && exit 1
	!(hash dnsproxy &> /dev/null) && echo "请安装dnsproxy程序[aurman -S dnsproxy]！" && exit 1
}

resolveip() {

	if [[ $1 =~ "^([0-9]{1,3}\.){3}[0-9]{1,3}$" ]]; then
		echo $1
	else
		local IP=$(dig $1 | grep -Ev "^$|^[[:space:]]*$|^[#;]" \
		| grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}$" \
		| head -1)
		[ -z "$IP" ] && return 1 || echo $IP
	fi
}

gerneral_config() {

	echo "创建配置文件..."
	ciphers="aes-256-gcm aes-192-gcm aes-128-gcm aes-256-ctr aes-192-ctr aes-128-ctr aes-256-cfb aes-192-cfb aes-128-cfb camellia-128-cfb camellia-192-cfb camellia-256-cfb xchacha20-ietf-poly1305 chacha20-ietf-poly1305 chacha20-ietf chacha20 salsa20 rc4-md5"
	echo "---------------------------------------"
	echo "|************ 创建配置信息 ************|"
	echo "---------------------------------------"
	echo -n "服务器地址："
	read ss_server_ip
	echo -n "服务器端口号："
	read ss_server_port
	echo -n "服务器密码："
	read ss_server_passwd
	echo "$ciphers" | tr " " "\n" | grep -n . | sed -e "s/:/) /g"
	echo -n "服务器加密方式："
	read ss_server_method
	[ -n "$ss_server_method" ] && ss_server_method="$(echo $ciphers | tr ' ' '\n' | sed -n "$ss_server_method"p)"
	ss_server_ip="$(resolveip $ss_server_ip)" || (echo "服务器ip解析失败！" && exit 1)
	cat > $config_path <<-EOF
	{
	    "server":"$ss_server_ip",
	    "server_port":$ss_server_port,
	    "local_address":"0.0.0.0",
	    "local_port":$local_port,
	    "password":"$ss_server_passwd",
	    "timeout":600,
	    "method":"$ss_server_method",
	    "fast_open": $fast_open
	}
	EOF

}

start_ss_redir() {

	echo "启动主进程..."
	# Start ss-redir
	$ss_redir -c $config_path -l $local_port -u -f /var/run/ss-redir.pid &> /dev/null

}

start_dnsproxy() {

	echo "启动dnsproxy进程..."
	# start dnsproxy
	$dnsproxy -T -R $remote_dns_ip -P $remote_dns_port -p $dns_port -d &> /dev/null

}

update() {
	echo "检查规则列表..."
	if [ ! -f "$gfwlist_path" -o "$1" = "rules" ]; then
		echo "下载gfwlist规则..."
		curl -kLo /tmp/gfwlist.conf https://github.com/hq450/fancyss/raw/master/rules/gfwlist.conf
		[ $? -ne 0 ] && echo "下载失败！请检查网络！" && exit 1
		install -D -m644 /tmp/gfwlist.conf "$gfwlist_path" &> /dev/null
		rm /tmp/gfwlist.conf
	fi

	if [ ! -f "$chnroute_path" -o "$1" = "rules" ]; then
		echo "下载大陆白名单规则..."
		curl -kLo /tmp/chnroute.txt https://github.com/hq450/fancyss/raw/master/rules/chnroute.txt
		[ $? -ne 0 ] && echo "下载失败！请检查网络！" && exit 1
		install -D -m644 /tmp/chnroute.txt "$chnroute_path" &> /dev/null
		rm /tmp/chnroute.txt
	fi

	if [ ! -f "$cdn_path" -o "$1" = "rules" ]; then
		echo "下载cdn规则..."
		curl -kLo /tmp/cdn.txt https://github.com/hq450/fancyss/raw/master/rules/cdn.txt
		[ $? -ne 0 ] && echo "下载失败！请检查网络！" && exit 1
		install -D -m644 /tmp/cdn.txt "$cdn_path" &> /dev/null
		rm /tmp/cdn.txt
	fi

	if [ "$1" = "script" ]; then
		echo "下载archss.sh..."
		curl -kLo /tmp/archss.sh https://github.com/monlor/Arch-Router-SS/raw/master/archss.sh
		[ $? -ne 0 ] && echo "下载失败！请检查网络！" && exit 1
		install -D -m755 /tmp/archss.sh "$ss_path/archss.sh" &> /dev/null
		rm /tmp/archss.sh
	fi
}

config_ipset() {

	echo "配置ipset列表..."
	ipset -! create white_list nethash && ipset flush white_list
	ipset -! create black_list nethash && ipset flush black_list
	if [ "$ss_mode" == "gfwlist" ]; then
		# gfwlist dnsmasq
		ipset -! create gfwlist nethash && ipset flush gfwlist
		cat /dev/null > /etc/dnsmasq.d/gfwlist_ipset.conf
		cat "$gfwlist_path" >> /etc/dnsmasq.d/gfwlist_ipset.conf
		sed -i "s/7913/$dns_port/g" /etc/dnsmasq.d/gfwlist_ipset.conf
	elif [ "$ss_mode" == "bypass" -o "$ss_mode" == "gamemode" ]; then
		# bypass ipset
		ipset -! create bypass nethash && ipset flush bypass
		sed -e "s/^/-A bypass &/g" "$chnroute_path" | ipset -R -!
	fi
	# black list ipset
	ip_tg="149.154.0.0/16 91.108.4.0/22 91.108.56.0/24 109.239.140.0/24 67.198.55.0/24 $remote_dns_ip"
	for ip in $ip_tg
	do
		ipset -! add black_list $ip >/dev/null 2>&1
	done

	ss_server_ip=$(cat $config_path | grep server | grep -oE "([0-9]{1,3}[\.]){3}[0-9]{1,3}")

	# white list ipset
	ip_lan="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4 $ss_server_ip $ss_cdn 223.5.5.5 223.6.6.6 114.114.114.114 114.114.115.115 1.2.4.8 210.2.4.8 112.124.47.27 114.215.126.16 180.76.76.76 119.29.29.29"
	for ip in $ip_lan
	do
		ipset -! add white_list $ip >/dev/null 2>&1
	done
	# add custom black list
	cat /dev/null > /etc/dnsmasq.d/wblist_ipset.conf
	cat "$black_path" | sed -E '/^$|^[#;]/d' | while read line
	do
		if [ -z "$(echo $line | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}")" ]; then
			echo "server=/.$line/127.0.0.1#$dns_port" >> /etc/dnsmasq.d/wblist_ipset.conf
			echo "ipset=/.$line/black_list" >> /etc/dnsmasq.d/wblist_ipset.conf
		else
			ipset -! add black_list $line &> /dev/null
		fi
	done
	# add custom white list
	cat "$white_path" | sed -E '/^$|^[#;]/d' | while read line
	do
		if [ -z "$(echo $line | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}")" ]; then
			echo "server=/.$line/$ss_cdn#$ss_cdn_port" >> /etc/dnsmasq.d/wblist_ipset.conf
			echo "ipset=/.$line/white_list" >> /etc/dnsmasq.d/wblist_ipset.conf
		else
			ipset -! add white_list $line &> /dev/null
		fi
	done
	# not gfwlist over cdn
	if [ "$ss_mode" != "gfwlist" ]; then
		# comment user's DNS
		sed -i "s/^[^#].*$ss_cdn#$ss_cdn_port/#&/" /etc/dnsmasq.conf
		# set default DNS over ss
		echo "server=127.0.0.1#$dns_port" >> /etc/dnsmasq.d/sscdn_ipset.conf
		cat "$cdn_path" | sed "s/^/server=&\/./g" | sed "s/$/\/&$ss_cdn#$ss_cdn_port/g" | sort | awk '{if ($0!=line) print;line=$0}' >> /etc/dnsmasq.d/sscdn_ipset.conf
	fi

}

create_nat_rules() {

	echo "创建NAT规则..."
	iptables -t nat -N SHADOWSOCKS
	iptables -t nat -A SHADOWSOCKS -p tcp -m set --match-set white_list dst -j RETURN
	if [ "$ss_mode" == "gfwlist" ]; then
		iptables -t nat -A SHADOWSOCKS -p tcp -m set --match-set black_list dst -j REDIRECT --to-ports "$local_port"
		iptables -t nat -A SHADOWSOCKS -p tcp -m set --match-set gfwlist dst -j REDIRECT --to-ports "$local_port"
	elif [ "$ss_mode" == "bypass" ]; then
		iptables -t nat -A SHADOWSOCKS -p tcp -m set --match-set black_list dst -j REDIRECT --to-ports "$local_port"
		iptables -t nat -A SHADOWSOCKS -p tcp -m set ! --match-set bypass dst -j REDIRECT --to-ports "$local_port"
	elif [ "$ss_mode" == "whole" ]; then
		iptables -t nat -A SHADOWSOCKS -p tcp -j REDIRECT --to-ports "$local_port"
	elif [ "$ss_mode" == "gamemode" ]; then
		iptables -t nat -A SHADOWSOCKS -p tcp -m set --match-set black_list dst -j REDIRECT --to-ports "$local_port"
		iptables -t nat -A SHADOWSOCKS -p tcp -m set ! --match-set bypass dst -j REDIRECT --to-ports "$local_port"
		# iptables -t nat -A SHADOWSOCKS -p udp -m set ! --match-set bypass dst -j REDIRECT --to-ports "$local_port"
		ip rule add fwmark 0x07 table 310 pref 789
		ip route add local 0.0.0.0/0 dev lo table 310
		iptables -t mangle -N SHADOWSOCKS
		iptables -t mangle -A SHADOWSOCKS -p udp -m set --match-set white_list dst -j RETURN
		iptables -t mangle -A SHADOWSOCKS -p udp -m set --match-set black_list dst -j TPROXY --on-port "$local_port" --tproxy-mark 0x07
		iptables -t mangle -A SHADOWSOCKS -p udp -m set ! --match-set bypass dst -j TPROXY --on-port "$local_port" --tproxy-mark 0x07
	else
		echo "启动模式错误！" && exit 1
	fi
	# chromecast
	[ -n "$lanip" ] && iptables -t nat -I PREROUTING -s $lanip/24 -p udp --dport 53 -m comment --comment "ss_chromecast" -j DNAT --to $lanip
	# forward
	iptables -t nat -I PREROUTING 1 -p tcp -j SHADOWSOCKS
	[ "$ss_mode" == "gamemode" ] && iptables -t mangle -I PREROUTING 1 -p udp -j SHADOWSOCKS
	# for router self
	iptables -t nat -I OUTPUT 1 -p tcp -j SHADOWSOCKS
	# add iptables config
	cat /dev/null > /etc/iptables/shadowsocks.rules
	iptables -t nat -S SHADOWSOCKS | grep SHADOWSOCKS >> /etc/iptables/shadowsocks.rules
	iptables -t nat -S PREROUTING | grep -E 'SHADOWSOCKS|chromecast' >> /etc/iptables/shadowsocks.rules
	iptables -t nat -S OUTPUT | grep SHADOWSOCKS >> /etc/iptables/shadowsocks.rules
	if [ "$ss_mode" == "gamemode" ]; then
		iptables -t mangle -S SHADOWSOCKS | grep SHADOWSOCKS >> /etc/iptables/shadowsocks.rules
		iptables -t mangle -S PREROUTING | grep SHADOWSOCKS >> /etc/iptables/shadowsocks.rules
	fi

}

stop_process() {
	echo "关闭主进程..."
	[ -n "$(pidof ss-redir)" ] && killall -9 ss-redir && rm -rf /var/run/ss-redir.pid
	[ -n "$(pidof dnsproxy)" ] && killall -9 dnsproxy
}

flush_nat() {

	echo "清除规则..."
	# flush shadowsocks rules
	eval "`iptables -t nat -S | grep SHADOWSOCKS | sed 1d | sed -e "s/-A/iptables -t nat -D/"`"
	iptables -t nat -D PREROUTING -p tcp -j SHADOWSOCKS >/dev/null 2>&1
	iptables -t nat -F SHADOWSOCKS > /dev/null 2>&1 && iptables -t nat -X SHADOWSOCKS > /dev/null 2>&1
	eval "`iptables -t mangle -S | grep SHADOWSOCKS | sed 1d | sed -e "s/-A/iptables -t mangle -D/"`"
	iptables -t mangle -D PREROUTING -p udp -j SHADOWSOCKS >/dev/null 2>&1
	iptables -t mangle -F SHADOWSOCKS >/dev/null 2>&1 && iptables -t mangle -X SHADOWSOCKS >/dev/null 2>&1
	iptables -t nat -D OUTPUT -p tcp -j SHADOWSOCKS &> /dev/null
	# flush chromecast rule
	eval `iptables -t nat -S | grep "ss_chromecast" | head -1 | sed -e "s/-A/iptables -t nat -D/"` &> /dev/null
	# flush ipset
	ipset -F bypass >/dev/null 2>&1 && ipset -X bypass >/dev/null 2>&1
	ipset -F white_list >/dev/null 2>&1 && ipset -X white_list >/dev/null 2>&1
	ipset -F black_list >/dev/null 2>&1 && ipset -X black_list >/dev/null 2>&1
	ipset -F gfwlist >/dev/null 2>&1 && ipset -X gfwlist >/dev/null 2>&1
	# remove_redundant_rule
	ip_rule_exist=`ip rule show | grep "fwmark 0x7 lookup 310" | grep -c 310`
	if [ ! -z "ip_rule_exist" ];then
		echo "清除重复的ip rule规则."
		until [ "$ip_rule_exist" = 0 ]
		do
			#ip rule del fwmark 0x07 table 310
			ip rule del fwmark 0x07 table 310 pref 789
			ip_rule_exist=`expr $ip_rule_exist - 1`
		done
	fi
	# remove_route_table
	echo "删除ip route规则"
	ip route del local 0.0.0.0/0 dev lo table 310 >/dev/null 2>&1
	# remove dnsmasq config
	rm -rf /etc/dnsmasq.d/gfwlist_ipset.conf
	rm -rf /etc/dnsmasq.d/sscdn_ipset.conf
	rm -rf /etc/dnsmasq.d/wblist_ipset.conf
	# remove iptables config
	rm -rf /etc/iptables/shadowsocks.rules
	# uncomment user's DNS
	sed -i "s/^#\(.*$ss_cdn#$ss_cdn_port\)/\1/" /etc/dnsmasq.conf
}

restart_dnsmasq() {
	# Restart dnsmasq
	echo "重启dnsmasq服务..."
	systemctl restart dnsmasq
	sleep 1
}

mount_resolv() {
	if [ "$modify_resolv" = "true" ]; then
		RESOLV=$(mktemp)
		chmod 644 $RESOLV
		cat > $RESOLV << EOF
# Generated by archss.sh
nameserver 127.0.0.1
EOF
		echo "生成 /etc/resolv.conf..."
		mount --bind $RESOLV /etc/resolv.conf
		rm $RESOLV
	fi
}

umount_resolv() {
	if [ "$modify_resolv" = "true" ]; then
		echo "释放 /etc/resolv.conf..."
		umount /etc/resolv.conf
	fi
}

check_status() {

	[ -n "$(pidof ss-redir)" ] && echo "ss-redir运行pid:$(pidof ss-redir)" || echo "ss-reidr未运行"
	[ -n "$(pidof dnsproxy)" ] && echo "dnsproxy运行pid:$(pidof dnsproxy)" || echo "dnsproxy未运行"
	[ -n "$(iptables -t nat -S | grep SHADOWSOCKS)" ] && echo "防火墙tcp规则已添加" || echo "防火墙tcp规则未添加"
	[ -n "$(iptables -t mangle -S | grep SHADOWSOCKS)" ] && echo "防火墙udp规则已添加" || echo "防火墙udp规则未添加"

}

stop() {
	env_check
	stop_process
	flush_nat
	restart_dnsmasq
	umount_resolv
}

start() {

	env_check
	[ ! -f "$config_path" ] && gerneral_config
	prepare "$1"
	echo "程序启动模式：【$ss_mode】"
	start_ss_redir
	update
	config_ipset
	create_nat_rules
	start_dnsproxy
	restart_dnsmasq
	mount_resolv
}

case "$1" in
	start) start "$2" ;;
	stop) stop ;;
	restart) stop; start "$2" ;;
	status) check_status ;;
	config) gerneral_config ;;
	update) update "$2" ;;
	install) install_scripts ;;
	*) help ;;
esac

#!/bin/sh
#contibuted by monlor & edward-p

ss_dir="/opt/archwrt-ss"
_conf="${ss_dir}/archwrt-ss.conf"

if [ ! -f "${_conf}" ]; then
	echo "No config file found! exiting..."
    exit 1
fi

source "${_conf}"

help() {
	cat <<-EOF
	Info:
	  Contibuted by monlor & edward-p
	Usage:
	  $0 {Command} {Option}
	Commands:
	  start | stop | restart | status | config | update
	Options:
	  gfwlist | bypass | gamemode | global
	Example:
	  $0 start bypass		Start with bypass mode
	  $0 restart gfwlist	Restart with gfwlist mode
	  $0 start			Start with default mode[${ss_mode}]
	  $0 config		Modify server config
	  $0 update		Update rules
	EOF

}

prepare() {

	[ ! -d "${ss_dir}" ] && mkdir -p "${ss_dir}"
	[ ! -f "${whitelist}" ] && touch "${whitelist}"
	[ ! -f "${blacklist}" ] && touch "${blacklist}"
	[ ! -d /etc/dnsmasq.d ] && mkdir -p /etc/dnsmasq.d
	[ -z "$(cat /etc/dnsmasq.conf | grep "^conf-dir")" ] && echo "conf-dir=/etc/dnsmasq.d/,*.conf" >> /etc/dnsmasq.conf
	[ "$(cat /proc/sys/net/ipv4/ip_forward)" != '1' ] && echo 1 > /proc/sys/net/ipv4/ip_forward
	# deal with ss mode
	if [ ! -z "$1" ]; then
		ss_mode="$1"
		sed -i "s,ss_mode=.*,ss_mode=\"$1\",g" "${_conf}"
	fi

}

env_check() {

	echo "Checking environment..."
	[ "$(whoami)" != "root" ] && echo "Please run as root!" && exit 1
	!(hash ss-redir &> /dev/null) && echo "Please install shadowsocks-libev!" && exit 1
	!(hash curl &> /dev/null) && echo "Please install curl!" && exit 1
	!(hash ipset &> /dev/null) && echo "Please install ipset!" && exit 1
	!(hash iptables &> /dev/null) && echo "Please install iptables！" && exit 1
	!(hash dig &> /dev/null) && echo "Please install bind-tools!" && exit 1
	!(hash dnsproxy-adguard &> /dev/null) && echo "Please install dnsproxy-adguard!" && exit 1
}

resolveip() {

	if [[ $1 =~ "^([0-9]{1,3}\.){3}[0-9]{1,3}$" ]]; then
		echo $1
	else
		local IP=$(dig $1 | grep -Ev "^$|^[[:space:]]*$|^[#;]" \
		| grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}$" \
		| head -1)
		[ -z "${IP}" ] && return 1 || echo ${IP}
	fi
}

generate_config() {

	echo "Creating config.json..."
	ciphers="aes-256-gcm aes-192-gcm aes-128-gcm aes-256-ctr aes-192-ctr aes-128-ctr aes-256-cfb aes-192-cfb aes-128-cfb camellia-128-cfb camellia-192-cfb camellia-256-cfb xchacha20-ietf-poly1305 chacha20-ietf-poly1305 chacha20-ietf chacha20 salsa20 rc4-md5"
	echo "---------------------------------------"
	echo "|*********** Configuration ***********|"
	echo "---------------------------------------"
	printf "Server:"
	read ss_server_ip
	printf "Port:"
	read ss_server_port
    printf "Local Port:"
    read local_port
	printf "Password:"
	read ss_server_passwd
    printf "Timeout:"
    read timeout
	echo "${ciphers}" | tr " " "\n" | grep -n . | sed -e "s/:/) /g"
	printf "Method:"
	read ss_server_method
    printf "Fast Open(true|false):"
    read fast_open
    printf "Plugin:"
    read plugin
    printf "Plugin Opts:"
    read plugin_opts
    [ -n "${ss_server_method}" ] && ss_server_method="$(echo ${ciphers} | tr ' ' '\n' | sed -n "${ss_server_method}"p)"
	ss_server_ip="$(resolveip ${ss_server_ip})" || (echo "resolve server ip failed!" && exit 1)
	cat > ${ss_config} <<-EOF
	{
		"server": "${ss_server_ip}",
		"server_port": ${ss_server_port},
		"local_address": "0.0.0.0",
		"local_port": ${local_port},
		"password": "${ss_server_passwd}",
		"timeout": ${timeout},
		"method": "${ss_server_method}",
		"mode": "tcp_and_udp",
		"fast_open": ${fast_open},
		"plugin": "${plugin}",
		"plugin_opts": "${plugin_opts}"
	}
	EOF

}

start_ss_redir() {

	echo "Starting ss-redir..."
	# Start ss-redir
	${ss_redir} -c ${ss_config} -f /var/run/ss-redir.pid &> /dev/null

}

start_dnsproxy() {

	echo "Starting dnsproxy..."
	# start dnsproxy
	nohup ${dnsproxy} -u "${dot_doh}" -p "${dp_port}" &> /dev/null &

}

update_rules() {
	echo "Checking rules..."
    if [ ! -f ${gfwlist} -o "$1" = "f" ]; then
	echo "Downloading gfwlist.txt..."
	curl -kLo /tmp/gfwlist.conf https://github.com/hq450/fancyss/raw/master/rules/gfwlist.conf
	[ $? -ne 0 ] && echo "Download failed! Check your connection!" && exit 1
	install -D -m644 /tmp/gfwlist.conf "${gfwlist}" &> /dev/null
	rm /tmp/gfwlist.conf
    fi

    if [ ! -f ${chnroute} -o "$1" = "f" ]; then
	echo "Downloading chnroute.txt..."
	curl -kLo /tmp/chnroute.txt https://github.com/hq450/fancyss/raw/master/rules/chnroute.txt
	[ $? -ne 0 ] && echo "Download failed! Check your connection!" && exit 1
	install -D -m644 /tmp/chnroute.txt "${chnroute}" &> /dev/null
	rm /tmp/chnroute.txt
    fi


    if [ ! -f ${cdn} -o "$1" = "f" ]; then
	echo "Downloading cdn.txt..."
	curl -kLo /tmp/cdn.txt https://github.com/hq450/fancyss/raw/master/rules/cdn.txt
	[ $? -ne 0 ] && echo "Download failed! Check your connection!" && exit 1
	install -D -m644 /tmp/cdn.txt "${cdn}" &> /dev/null
	rm /tmp/cdn.txt
    fi
}

config_ipset() {

	echo "Setting up ipset..."
	ipset -! create white_list nethash && ipset flush white_list
	ipset -! create black_list nethash && ipset flush black_list
	if [ "${ss_mode}" = "gfwlist" ]; then
		# gfwlist dnsmasq
		ipset -! create gfwlist nethash && ipset flush gfwlist
		cat "${gfwlist}" > /etc/dnsmasq.d/20-gfwlist_ipset.conf
		sed -i "s/7913/${dp_port}/g" /etc/dnsmasq.d/20-gfwlist_ipset.conf
	elif [ "${ss_mode}" = "bypass" -o "${ss_mode}" = "gamemode" ]; then
		# bypass ipset
		ipset -! create bypass nethash && ipset flush bypass
		sed -e "s/^/-A bypass &/g" "${chnroute}" | ipset -R -!
	fi

	# Telegram IPs
	ip_tg="149.154.0.0/16 91.108.4.0/22 91.108.56.0/24 109.239.140.0/24 67.198.55.0/24"
	for ip in ${ip_tg}
	do
		ipset -! add black_list ${ip} &>/dev/null
	done

	ss_server_ip=$(cat ${ss_config} | grep server | grep -oE "([0-9]{1,3}[\.]){3}[0-9]{1,3}")

	# white list ipset
	ip_lan="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4 ${ss_server_ip} ${china_dns} 223.5.5.5 223.6.6.6 114.114.114.114 114.114.115.115 1.2.4.8 210.2.4.8 112.124.47.27 114.215.126.16 180.76.76.76 119.29.29.29"
	for ip in ${ip_lan}
	do
		ipset -! add white_list ${ip} &>/dev/null
	done
	# add custom black list
	cat /dev/null > /etc/dnsmasq.d/20-wblist_ipset.conf
	cat "${blacklist}" | sed -E '/^$|^[#;]/d' | while read line
	do
		if [ -z "$(echo ${line} | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}")" ]; then
			echo "server=/.${line}/127.0.0.1#${dp_port}" >> /etc/dnsmasq.d/20-wblist_ipset.conf
			echo "ipset=/.${line}/black_list" >> /etc/dnsmasq.d/20-wblist_ipset.conf
		else
			ipset -! add black_list ${line} &> /dev/null
		fi
	done
	# add custom white list
	cat "${whitelist}" | sed -E '/^$|^[#;]/d' | while read line
	do
		if [ -z "$(echo ${line} | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}")" ]; then
			echo "server=/.${line}/${china_dns}#${china_dns_port}" > /etc/dnsmasq.d/20-wblist_ipset.conf
			echo "ipset=/.${line}/white_list" > /etc/dnsmasq.d/20-wblist_ipset.conf
		else
			ipset -! add white_list ${line} &> /dev/null
		fi
	done
	# not gfwlist over cdn
	if [ "${ss_mode}" = "gfwlist" ]; then
		# Setup China DNS
		cat > /etc/dnsmasq.d/10-dns.conf <<-EOF
		no-resolv
		no-poll
		expand-hosts
		server=${china_dns}#${china_dns_port}
		EOF
	else
		# set default DNS over DoT
		cat > /etc/dnsmasq.d/10-dns.conf <<-EOF
		no-resolv
		no-poll
		expand-hosts
		server=127.0.0.1#${dp_port}
		EOF
		# set cdn over China DNS
		cat "${cdn}" | sed "s/^/server=&\/./g" | sed "s/$/\/&${china_dns}#${china_dns_port}/g" |
		sort | awk '{if ($0!=line) print;line=$0}' > /etc/dnsmasq.d/20-sscdn_ipset.conf
	fi

}

create_nat_rules() {

	echo "Setting up NAT table..."
	iptables -t nat -N SHADOWSOCKS
	iptables -t nat -A SHADOWSOCKS -p tcp -m set --match-set white_list dst -j RETURN
	if [ "${ss_mode}" = "gfwlist" ]; then
		iptables -t nat -A SHADOWSOCKS -p tcp -m set --match-set black_list dst -j REDIRECT --to-ports "${local_port}"
		iptables -t nat -A SHADOWSOCKS -p tcp -m set --match-set gfwlist dst -j REDIRECT --to-ports "${local_port}"
	elif [ "${ss_mode}" = "bypass" ]; then
		iptables -t nat -A SHADOWSOCKS -p tcp -m set --match-set black_list dst -j REDIRECT --to-ports "${local_port}"
		iptables -t nat -A SHADOWSOCKS -p tcp -m set ! --match-set bypass dst -j REDIRECT --to-ports "${local_port}"
	elif [ "${ss_mode}" = "global" ]; then
		iptables -t nat -A SHADOWSOCKS -p tcp -j REDIRECT --to-ports "${local_port}"
	elif [ "${ss_mode}" = "gamemode" ]; then
		iptables -t nat -A SHADOWSOCKS -p tcp -m set --match-set black_list dst -j REDIRECT --to-ports "${local_port}"
		iptables -t nat -A SHADOWSOCKS -p tcp -m set ! --match-set bypass dst -j REDIRECT --to-ports "${local_port}"
		# iptables -t nat -A SHADOWSOCKS -p udp -m set ! --match-set bypass dst -j REDIRECT --to-ports "${local_port}"
		ip rule add fwmark 0x07 table 310 pref 789
		ip route add local 0.0.0.0/0 dev lo table 310
		iptables -t mangle -N SHADOWSOCKS
		iptables -t mangle -A SHADOWSOCKS -p udp -m set --match-set white_list dst -j RETURN
		iptables -t mangle -A SHADOWSOCKS -p udp -m set --match-set black_list dst -j TPROXY --on-port "${local_port}" --tproxy-mark 0x07
		iptables -t mangle -A SHADOWSOCKS -p udp -m set ! --match-set bypass dst -j TPROXY --on-port "${local_port}" --tproxy-mark 0x07
		
		iptables -t mangle -N SS_OUTPUT
		iptables -t mangle -A SS_OUTPUT -p udp -j RETURN -m set --match-set white_list dst
		iptables -t mangle -A SS_OUTPUT -p udp -m set --match-set black_list dst -j MARK --set-mark 0x07
		iptables -t mangle -A SS_OUTPUT -p udp -m set ! --match-set bypass dst -j MARK --set-mark 0x07

	else
		echo "Wrong proxy mode!" && exit 1
	fi

	#PREROUTING

	# dns_redir
	[ -n "${lanip}" ] && iptables -t nat -I PREROUTING -s ${lanip}/24 -p udp --dport 53 -m comment --comment "dns_redir" -j DNAT --to ${lanip}
	# forward
	iptables -t nat -I PREROUTING 1 -p tcp -j SHADOWSOCKS
	[ "${ss_mode}" = "gamemode" ] && iptables -t mangle -I PREROUTING 1 -p udp -j SHADOWSOCKS
	# for router self
	iptables -t nat -I OUTPUT 1 -p tcp -j SHADOWSOCKS
	[ "${ss_mode}" = "gamemode" ] && iptables -t mangle -I OUTPUT 1 -p udp -j SS_OUTPUT

}

stop_process() {
	echo "Stopping process..."
	[ -n "$(pidof ss-redir)" ] && killall -9 ss-redir && rm -rf /var/run/ss-redir.pid
	[ -n "$(pidof dnsproxy-adguard)" ] && killall -9 dnsproxy-adguar
}

flush_nat() {

	echo "Clear rules..."
	# flush shadowsocks rules
	eval "`iptables -t nat -S | grep SHADOWSOCKS | sed 1d | sed -e "s/-A/iptables -t nat -D/"`"
	iptables -t nat -D PREROUTING -p tcp -j SHADOWSOCKS &>/dev/null
	iptables -t mangle -D OUTPUT -p udp -j SS_OUTPUT
	iptables -t nat -F SHADOWSOCKS > /dev/null 2>&1 && iptables -t nat -X SHADOWSOCKS > /dev/null 2>&1
	eval "`iptables -t mangle -S | grep SHADOWSOCKS | sed 1d | sed -e "s/-A/iptables -t mangle -D/"`"
	iptables -t mangle -D PREROUTING -p udp -j SHADOWSOCKS &>/dev/null
	iptables -t mangle -F SHADOWSOCKS &>/dev/null && iptables -t mangle -X SHADOWSOCKS &>/dev/null
	iptables -t mangle -F SS_OUTPUT &>/dev/null && iptables -t mangle -X SS_OUTPUT &>/dev/null
	iptables -t nat -D OUTPUT -p tcp -j SHADOWSOCKS &> /dev/null
	# flush dns_redir rule
	eval `iptables -t nat -S | grep "dns_redir" | head -1 | sed -e "s/-A/iptables -t nat -D/"` &> /dev/null
	# flush ipset
	ipset -F bypass &>/dev/null && ipset -X bypass &>/dev/null
	ipset -F white_list &>/dev/null && ipset -X white_list &>/dev/null
	ipset -F black_list &>/dev/null && ipset -X black_list &>/dev/null
	ipset -F gfwlist &>/dev/null && ipset -X gfwlist &>/dev/null
	# remove_redundant_rule
	ip_rule_exist=`ip rule show | grep "fwmark 0x7 lookup 310" | grep -c 310`
	if [ ! -z "ip_rule_exist" ];then
		echo "Clearing duplicated rules..."
		until [ "${ip_rule_exist}" = 0 ]
		do
			#ip rule del fwmark 0x07 table 310
			ip rule del fwmark 0x07 table 310 pref 789
			ip_rule_exist=`expr ${ip_rule_exist} - 1`
		done
	fi
	# remove_route_table
	echo "Clearing rules..."
	ip route del local 0.0.0.0/0 dev lo table 310 &>/dev/null
	
	
	# restore DNS to China DNS
	cat > /etc/dnsmasq.d/10-dns.conf <<-EOF
	no-resolv
	no-poll
	expand-hosts
	server=${china_dns}#${china_dns_port}
	EOF
	# remove dnsmasq config
	rm -rf /etc/dnsmasq.d/20-gfwlist_ipset.conf
	rm -rf /etc/dnsmasq.d/20-sscdn_ipset.conf
	rm -rf /etc/dnsmasq.d/20-wblist_ipset.conf
}

restart_dnsmasq() {
	# Restart dnsmasq
	echo "Restarting dnsmasq..."
	systemctl restart dnsmasq
	sleep 1
}

mount_resolv() {
	if [ "${overwrite_resolv}" = "true" ]; then
		RESOLV=$(mktemp)
		chmod 644 ${RESOLV}
		cat > ${RESOLV} <<-EOF
		# Generated by archwrt-ss.sh
		nameserver 127.0.0.1
		EOF

        echo "Binding /etc/resolv.conf..."
		mount --bind ${RESOLV} /etc/resolv.conf
		rm ${RESOLV}
	fi
}

umount_resolv() {
	if [ "${overwrite_resolv}" = "true" ]; then
		echo "Releasing /etc/resolv.conf..."
		umount /etc/resolv.conf
	fi
}

check_status() {

	[ -n "$(pidof ss-redir)" ] && echo "ss-redir running pid:$(pidof ss-redir)" || echo "ss-reidr stoped"
	[ -n "$(pidof dnsproxy-adguard)" ] && echo "dnsproxy running pid:$(pidof dnsproxy-adguard)" || echo "dnsproxy stopped"
	[ -n "$(iptables -t nat -S | grep SHADOWSOCKS)" ] && echo "nat rules added" || echo "no nat rules"
	[ -n "$(iptables -t mangle -S | grep SHADOWSOCKS)" ] && echo "udp rules added" || echo "no udp rules"

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
	if [ ! -f "${ss_config}" ]; then
        generate_config
    else
        local_port=$(cat ${ss_config} |
            grep "local_port" |
            sed 's,[ "A-z:,],,g')
    fi

	prepare "$1"
	echo "Proxy Mode: [${ss_mode}]"
	start_ss_redir
	update_rules
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
	config) generate_config ;;
	update) update_rules "f" ;;
	*) help ;;
esac

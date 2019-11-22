#!/bin/bash
#contibuted by monlor & edward-p

ss_config_dir="/etc/shadowsocks"
ss_dir="/etc/archwrt/ss"
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
		  ${0##/*/} {Command} {Option} {Config File}
		Commands:
		  start | stop | restart | status | update
		Options:
		  gfwlist | bypass | gamemode | global
		Config File:
		  Specify which config.json to use. by default the script will use the last one used.
		Example:
		  ${0##/*/} start bypass          Start with bypass mode
		  ${0##/*/} restart gfwlist       Restart with gfwlist mode
		  ${0##/*/} restart bypass sfo2   Retart with bypass mode using ${ss_config_dir}/sfo2.json
		  ${0##/*/} restart sfo2          Retart using ${ss_config_dir}/sfo2.json
		  ${0##/*/} start                 Start with default mode [current:${ss_mode}]
		  ${0##/*/} update                Update rules
	EOF

}

prepare() {

	[ ! -d "${ss_dir}" ] && mkdir -p "${ss_dir}"
	[ ! -f "${speciallist}" ] && touch "${speciallist}"
	[ ! -f "${whitelist}" ] && touch "${whitelist}"
	[ ! -f "${blacklist}" ] && touch "${blacklist}"
	[ ! -d /etc/dnsmasq.d ] && mkdir -p /etc/dnsmasq.d
	! grep -q "^conf-dir" /etc/dnsmasq.conf &&
		echo "conf-dir=/etc/dnsmasq.d/,*.conf" >>/etc/dnsmasq.conf
	[ "$(cat /proc/sys/net/ipv4/ip_forward)" != '1' ] && echo 1 >/proc/sys/net/ipv4/ip_forward

	while [ $# -gt 0 ]; do
		case "$1" in
		gfwlist | bypass | gamemode | global)
			ss_mode="$1"
			sed -i "s,ss_mode=.*,ss_mode=\"$1\",g" "${_conf}"
			shift
			;;
		#"") shift ;;
		*)
			if [ ! -f "${ss_config_dir}/$1.json" ]; then
				echo "No shadowsocks config file found: ${ss_config_dir}/$1.json !" 1>&2 && exit 1
			fi
			if [ "${ss_config}" != "$1" ]; then
				ss_config="$1"
				sed -i "s,ss_config=.*,ss_config=\"${ss_config}\",g" "${_conf}"
			fi
			shift
			;;
		esac
	done

	ss_server_ip=$(grep "server" "${ss_config_dir}/${ss_config}.json" | grep -oE "([0-9]{1,3}[\.]){3}[0-9]{1,3}")
	local_port=$(grep "local_port" "${ss_config_dir}/${ss_config}.json" | grep -oE "[0-9]+")
}

env_check() {

	echo "Checking environment..."
	[ "$(whoami)" != "root" ] && echo "Please run as root!" && exit 1
	! hash ss-redir &>/dev/null && echo "Please install shadowsocks-libev!" && exit 1
	! hash curl &>/dev/null && echo "Please install curl!" && exit 1
	! hash ipset &>/dev/null && echo "Please install ipset!" && exit 1
	! hash iptables &>/dev/null && echo "Please install iptables！" && exit 1
	[ -z ${puredns_port} ] && echo "Please set puredns_port in ${_conf}!" && exit 1
}

start_ss_redir() {

	echo "Starting ss-redir..."
	# Start ss-redir
    (systemctl start shadowsocks-libev-redir@"${ss_config}".service &) || true

}

update_rules() {
	echo "Checking rules..."
	local URL="https://github.com/hq450/fancyss/raw/master"
	if [ ! -f "${gfwlist}" ] || [ "$1" = "f" ]; then
		echo "Downloading gfwlist.txt..."
		! curl -kLo /tmp/gfwlist.conf "$URL/rules/gfwlist.conf" &&
			echo "Download failed! Check your connection!" && exit 1
		install -D -m644 /tmp/gfwlist.conf "${gfwlist}" &>/dev/null
		rm /tmp/gfwlist.conf
	fi

	if [ ! -f "${chnroute}" ] || [ "$1" = "f" ]; then
		echo "Downloading chnroute.txt..."
		! curl -kLo /tmp/chnroute.txt "$URL/rules/chnroute.txt" &&
			echo "Download failed! Check your connection!" && exit 1
		install -D -m644 /tmp/chnroute.txt "${chnroute}" &>/dev/null
		rm /tmp/chnroute.txt
	fi

	if [ ! -f "${cdn}" ] || [ "$1" = "f" ]; then
		echo "Downloading cdn.txt..."
		! curl -kLo /tmp/cdn.txt "$URL/rules/cdn.txt" &&
			echo "Download failed! Check your connection!" && exit 1
		install -D -m644 /tmp/cdn.txt "${cdn}" &>/dev/null
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
		cat "${gfwlist}" >/etc/dnsmasq.d/20-gfwlist_ipset.conf
		sed -i "s/7913/${puredns_port}/g" /etc/dnsmasq.d/20-gfwlist_ipset.conf
	elif [ "${ss_mode}" = "bypass" ] || [ "${ss_mode}" = "gamemode" ]; then
		# bypass ipset
		ipset -! create bypass nethash && ipset flush bypass
		sed -e "s/^/-A bypass &/g" "${chnroute}" | ipset -R -!
	fi

	# Telegram IPs
	ip_tg="149.154.0.0/16 91.108.4.0/22 91.108.56.0/24 109.239.140.0/24 67.198.55.0/24"
	for ip in ${ip_tg}; do
		ipset -! add black_list "${ip}" &>/dev/null
	done

	# white list ipset
	local ip_whitelist=(
		'0.0.0.0/8'
		'10.0.0.0/8'
		'100.64.0.0/10'
		'127.0.0.0/8'
		'169.254.0.0/16'
		'172.16.0.0/12'
		'192.168.0.0/16'
		'224.0.0.0/4'
		'240.0.0.0/4'
		"${ss_server_ip}"
		"${china_dns}"
		'223.5.5.5'
		'223.6.6.6'
		'114.114.114.114'
		'114.114.115.115'
		'1.2.4.8'
		'210.2.4.8'
		'112.124.47.27'
		'114.215.126.16'
		'180.76.76.76'
		'119.29.29.29')
	for ip in "${ip_whitelist[@]}"; do
		ipset -! add white_list "${ip}" &>/dev/null
	done
	# add custom black list
	truncate -s 0 /etc/dnsmasq.d/20-wblist_ipset.conf
	sed -E '/^$|^[#;]/d' "${blacklist}" | while read -r line; do
		if ! echo "${line}" | grep -qE "([0-9]{1,3}[\.]){3}[0-9]{1,3}"; then
			echo "server=/.${line}/127.0.0.1#${puredns_port}" >>/etc/dnsmasq.d/20-wblist_ipset.conf
			echo "ipset=/.${line}/black_list" >>/etc/dnsmasq.d/20-wblist_ipset.conf
		else
			ipset -! add black_list "${line}" &>/dev/null
		fi
	done
	# add custom white list
	sed -E '/^$|^[#;]/d' "${whitelist}" | while read -r line; do
		if ! echo "${line}" | grep -qE "([0-9]{1,3}[\.]){3}[0-9]{1,3}"; then
			echo "server=/.${line}/${china_dns}#${china_dns_port}" >>/etc/dnsmasq.d/20-wblist_ipset.conf
			echo "ipset=/.${line}/white_list" >>/etc/dnsmasq.d/20-wblist_ipset.conf
		else
			ipset -! add white_list "${line}" &>/dev/null
		fi
	done

	# add speciallist
	truncate -s 0 /etc/dnsmasq.d/30-special_list.conf
	if [ -n "${special_dns_port}" ] && [ -n "${special_dns}" ]; then
		sed -E '/^$|^[#;]/d' "${speciallist}" | while read -r line; do
			echo "server=/.${line}/${special_dns}#${special_dns_port}" >>/etc/dnsmasq.d/30-special_list.conf
		done
	fi

	# not gfwlist over cdn
	if [ "${ss_mode}" = "gfwlist" ]; then
		# Setup China DNS
		cat >/etc/dnsmasq.d/10-dns.conf <<-EOF
			no-resolv
			expand-hosts
			server=${china_dns}#${china_dns_port}
		EOF

	else
		# set default DNS over DoT
		cat >/etc/dnsmasq.d/10-dns.conf <<-EOF
			no-resolv
			expand-hosts
			server=127.0.0.1#${puredns_port}
		EOF

		# set cdn domains over CDN DNS
		sed "s/^/server=&\/./g" "${cdn}" | sed "s/$/\/&${cdn_dns}#${cdn_dns_port}/g" |
			sort | awk '{if ($0!=line) print;line=$0}' >/etc/dnsmasq.d/20-sscdn_ipset.conf
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

stop_service() {
	echo "Stopping process..."

    systemctl stop shadowsocks-libev-redir@"${ss_config}"
}

flush_nat() {

	echo "Clear rules..."
	# flush shadowsocks rules
	eval "$(iptables -t nat -S | grep SHADOWSOCKS | sed 1d | sed -e "s/-A/iptables -t nat -D/")"
	iptables -t nat -D PREROUTING -p tcp -j SHADOWSOCKS &>/dev/null
	iptables -t mangle -D OUTPUT -p udp -j SS_OUTPUT &>/dev/null
	iptables -t nat -F SHADOWSOCKS >/dev/null 2>&1 && iptables -t nat -X SHADOWSOCKS >/dev/null 2>&1
	eval "$(iptables -t mangle -S | grep SHADOWSOCKS | sed 1d | sed -e "s/-A/iptables -t mangle -D/")"
	iptables -t mangle -D PREROUTING -p udp -j SHADOWSOCKS &>/dev/null
	iptables -t mangle -F SHADOWSOCKS &>/dev/null && iptables -t mangle -X SHADOWSOCKS &>/dev/null
	iptables -t mangle -F SS_OUTPUT &>/dev/null && iptables -t mangle -X SS_OUTPUT &>/dev/null
	iptables -t nat -D OUTPUT -p tcp -j SHADOWSOCKS &>/dev/null
	# flush dns_redir rule
	eval "$(iptables -t nat -S | grep "dns_redir" | head -1 | sed -e "s/-A/iptables -t nat -D/")" &>/dev/null
	# flush ipset
	ipset -F bypass &>/dev/null && ipset -X bypass &>/dev/null
	ipset -F white_list &>/dev/null && ipset -X white_list &>/dev/null
	ipset -F black_list &>/dev/null && ipset -X black_list &>/dev/null
	ipset -F gfwlist &>/dev/null && ipset -X gfwlist &>/dev/null
	# remove_redundant_rule
	local ip_rule_exist
	ip_rule_exist="$(ip rule show | grep "fwmark 0x7 lookup 310" | grep -c 310)"
	if [ -n "${ip_rule_exist}" ]; then
		echo "Clearing duplicated rules..."
		until [ "${ip_rule_exist}" = 0 ]; do
			#ip rule del fwmark 0x07 table 310
			ip rule del fwmark 0x07 table 310 pref 789
			ip_rule_exist=$((ip_rule_exist - 1))
		done
	fi
	# remove_route_table
	echo "Clearing rules..."
	ip route del local 0.0.0.0/0 dev lo table 310 &>/dev/null

	# restore DNS to China DNS
	cat >/etc/dnsmasq.d/10-dns.conf <<-EOF
		no-resolv
		no-poll
		expand-hosts
		server=${china_dns}#${china_dns_port}
	EOF
	# remove dnsmasq config
	rm -rf /etc/dnsmasq.d/20-gfwlist_ipset.conf
	rm -rf /etc/dnsmasq.d/20-sscdn_ipset.conf
	rm -rf /etc/dnsmasq.d/20-wblist_ipset.conf
	rm -rf /etc/dnsmasq.d/30-special_list.conf
}

restart_dnsmasq() {
	# Restart dnsmasq
	echo "Restarting dnsmasq..."
    systemctl restart dnsmasq
}

stop_dnsmasq() {
	# Restart dnsmasq
	echo "Stopping dnsmasq..."
    systemctl stop dnsmasq
}

mount_resolv() {
	if [ "${overwrite_resolv}" = "true" ]; then
		local RESOLV
		RESOLV="$(mktemp)"
		chmod 644 "${RESOLV}"
		cat >"${RESOLV}" <<-EOF
			# Generated by archwrt-ss.sh
			nameserver 127.0.0.1
		EOF

		echo "Binding /etc/resolv.conf..."
		mount --bind "${RESOLV}" /etc/resolv.conf
		rm "${RESOLV}"
	fi
}

umount_resolv() {
	if mount | grep -q '/etc/resolv.conf'; then
		echo "Releasing /etc/resolv.conf..."
		umount /etc/resolv.conf &>/dev/null
	fi
	if [ -f "/run/NetworkManager/resolv.conf" ]; then
		cat "/run/NetworkManager/resolv.conf" > "/etc/resolv.conf"
	fi
}

check_status() {
	echo '----------- status --------------'
	systemctl status --no-pager shadowsocks-libev-redir@"${ss_config}"
	echo '---------------------------------'
	systemctl status --no-pager "${puredns_service_name}"
	echo '---------------------------------'
	iptables -t nat -S | grep -q SHADOWSOCKS && echo "NAT rules added with [${ss_mode}]." || echo "No NAT rules added."
	iptables -t mangle -S | grep -q SHADOWSOCKS && echo "UDP rules added." || echo "No UDP rules added."
	mount | grep -q '/etc/resolv.conf' && echo "/etc/resolv.conf mounted with --bind" || echo "/etc/resolv.conf not changed."

}

stop() {
	env_check
	stop_service
	flush_nat
	if [ -n "${lanip}" ]; then
		restart_dnsmasq
	else
		stop_dnsmasq
	fi
	umount_resolv
}

start() {
	env_check

	prepare "$@"
	echo "Proxy Mode: [${ss_mode}]"
	start_ss_redir
	update_rules
	config_ipset
	create_nat_rules
	restart_dnsmasq
	mount_resolv
}

case "$1" in
start)
	shift
	start "$@"
	;;
stop) stop ;;
restart)
	shift
	stop
	start "$@"
	;;
status) check_status ;;
update) update_rules "f" ;;
*) help ;;
esac

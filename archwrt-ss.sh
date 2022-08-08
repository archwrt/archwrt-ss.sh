#!/bin/bash
#contibuted by monlor & edward-p

ss_dir="/etc/archwrt/ss"
_conf="${ss_dir}/archwrt-ss.conf"
smartdns_config_dir="/etc/smartdns"
smartdns_config="${smartdns_config_dir}/smartdns.conf"
smartdns_gfwlist="archwrt-ss.gfwlist.conf"
smartdns_wblist="archwrt-ss.wblist.conf"

if [ ! -f "${_conf}" ]; then
	echo "No config file found! exiting..."
	exit 1
fi

source "${_conf}"

if [ "${working_mode}" = "ss" ]; then
	ss_config_dir="/etc/shadowsocks-rust"
elif [ "${working_mode}" = "v2ray" ]; then
	ss_config_dir="/etc/v2ray"
else
	echo "working_mode not configured in $_conf"
	exit 1
fi

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
	[ ! -f "${whitelist}" ] && touch "${whitelist}"
	[ ! -f "${blacklist}" ] && touch "${blacklist}"
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
				echo "No shadowsocks/v2ray config file found: ${ss_config_dir}/$1.json !" 1>&2 && exit 1
			fi
			if [ "${ss_config}" != "$1" ]; then
				ss_config="$1"
				sed -i "s,ss_config=.*,ss_config=\"${ss_config}\",g" "${_conf}"
			fi
			shift
			;;
		esac
	done

	if [ "${working_mode}" = "v2ray" ]; then
		ss_server="$(grep \"address\" "${ss_config_dir}/${ss_config}.json" | sed -E 's/"|,|:/ /g' | awk '{print $ 2}')"
	elif [ "${working_mode}" = "ss" ]; then
		ss_server="$(grep \"server\" "${ss_config_dir}/${ss_config}.json" | sed -E 's/"|,|:/ /g' | awk '{print $ 2}')"
	fi
	if [[ ! "${ss_server}" =~ "([0-9]{1,3}[\.]){3}[0-9]{1,3}" ]]; then
		ss_server_ip="$ss_server"
	else
		ss_server_ip="$(ping -4 -q -c 1 -s 0 -W 1 -w 1 "$ss_server" | head -n 1 | sed -n 's/[^(]*(\([^)]*\)).*/\1/p')"
	fi

	if [ "${working_mode}" = "v2ray" ]; then
		local_port=$(grep "port" "${ss_config_dir}/${ss_config}.json" | grep -oE "[0-9]+" | head -1)
	elif [ "${working_mode}" = "ss" ]; then
		local_port=$(grep "local_port" "${ss_config_dir}/${ss_config}.json" | grep -oE "[0-9]+")
	fi
}

env_check() {

	echo "Checking environment..."
	[ "$(whoami)" != "root" ] && echo "Please run as root!" && exit 1
	! hash sslocal-rust &>/dev/null && ! hash v2ray &>/dev/null && echo "Please install shadowsocks-rust or v2ray!" && exit 1
	! hash curl &>/dev/null && echo "Please install curl!" && exit 1
	! hash ipset &>/dev/null && echo "Please install ipset!" && exit 1
	! hash iptables &>/dev/null && echo "Please install iptables！" && exit 1
}

start_ss_redir() {

	echo "Starting..."
	# Start redir
	if [ "${working_mode}" = "ss" ]; then
		(systemd-run --unit="sslocal-rust@${ss_config}" sslocal-rust -c "${ss_config_dir}/${ss_config}.json" &) || true
	elif [ "${working_mode}" = "v2ray" ]; then
		(systemctl start v2ray@"${ss_config}".service &) || true
	fi
}

update_rules() {
  if [ "${ss_mode}" = "global" ] && [ "$1" != "f" ]; then
    return 0
  fi
  echo "Checking rules..."
	if [ ! -f "${gfwlist}" ] || [ "$1" = "f" ]; then
		echo "Downloading gfwlist.conf..."
		! curl -kLo /tmp/gfwlist.conf "https://cdn.jsdelivr.net/gh/Apocalypsor/SmartDNS-GFWList@master/smartdns_gfw_domain.conf" &&
			echo "Download failed! Check your connection!" && exit 1
    grep '^nameserver' /tmp/gfwlist.conf | sed -E 's/^nameserver/ipset/g;s/GFW$/gfwlist/g' > "${gfwlist}"
		rm /tmp/gfwlist.conf
	fi

	if [ ! -f "${chnroute}" ] || [ "$1" = "f" ]; then
		echo "Downloading chnroute.txt..."
    ! curl -kL "https://cdn.jsdelivr.net/gh/soffchen/GeoIP2-CN@release/CN-ip-cidr.txt" > /tmp/chnroute.txt &&
			echo "Download failed! Check your connection!" && exit 1
		install -D -m644 /tmp/chnroute.txt "${chnroute}" &>/dev/null
		rm /tmp/chnroute.txt
	fi
}

config_smartdns() {
  # Setup smartdns 
  cat >"${smartdns_config}" <<-EOF
		bind [::]:${smartdns_port}
		cache-size ${smartdns_cache_size}
		log-level ${smartdns_log_level}
		rr-ttl-min 60
	EOF

  if [ "$1" = "start" ]; then
    if [ "${ss_mode}" = "gfwlist" ]; then
      echo "conf-file ${smartdns_gfwlist}" >> "${smartdns_config}"
    fi
    echo "conf-file ${smartdns_wblist}" >> "${smartdns_config}"
  fi

  for conf_file in ${smartdns_china_list[@]} \
    ${smartdns_custom_list[@]}; do
    echo "conf-file ${conf_file}" >> "${smartdns_config}"
  done

  for dns in ${smartdns_china[@]}; do
    echo "server ${dns} -group china -exclude-default-group" >> "${smartdns_config}"
  done

  for dns in ${smartdns_dns[@]}; do
    echo "server ${dns}" >> "${smartdns_config}"
  done
  for dns in ${smartdns_dot[@]}; do
    echo "server-tls ${dns}" >> "${smartdns_config}"
  done
  for dns in ${smartdns_doh[@]}; do
    echo "server-https ${dns}" >> "${smartdns_config}"
  done

}

config_ipset() {

	echo "Setting up ipset..."
	ipset -! create white_list nethash && ipset flush white_list
	ipset -! create black_list nethash && ipset flush black_list
	if [ "${ss_mode}" = "gfwlist" ]; then
		# gfwlist smartdns
		ipset -! create gfwlist nethash && ipset flush gfwlist
		ln -s "${gfwlist}" "${smartdns_config_dir}/${smartdns_gfwlist}"
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
		${smartdns_china[@]}
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
	truncate -s 0 "${smartdns_config_dir}/${smartdns_wblist}"
	sed -E '/^$|^[#;]/d' "${blacklist}" | while read -r line; do
  if ! echo "${line}" | grep -qE "([0-9]{1,3}[\.]){3}[0-9]{1,3}"; then
			echo "ipset /.${line}/black_list" >> "${smartdns_config_dir}/${smartdns_wblist}"
		else
			ipset -! add black_list "${line}" &>/dev/null
		fi
	done

	#add server domain to white list
	if [[ ! "${ss_server}" =~ "([0-9]{1,3}[\.]){3}[0-9]{1,3}" ]]; then
		echo "ipset /${ss_server}/white_list" >> "${smartdns_config_dir}/${smartdns_wblist}"
	fi

	# add custom white list
	sed -E '/^$|^[#;]/d' "${whitelist}" | while read -r line; do
		if ! echo "${line}" | grep -qE "([0-9]{1,3}[\.]){3}[0-9]{1,3}"; then
			echo "ipset /.${line}/white_list" >> "${smartdns_config_dir}/${smartdns_wblist}"
		else
			ipset -! add white_list "${line}" &>/dev/null
		fi
	done

  config_smartdns start

}


create_nat_rules() {

	echo "Setting up NAT table..."
	iptables -w -t nat -N SHADOWSOCKS
	iptables -w -t nat -A SHADOWSOCKS -p tcp -m set --match-set white_list dst -j RETURN
	if [ "${ss_mode}" = "gfwlist" ]; then
		iptables -w -t nat -A SHADOWSOCKS -p tcp -m set --match-set black_list dst -j REDIRECT --to-ports "${local_port}"
		iptables -w -t nat -A SHADOWSOCKS -p tcp -m set --match-set gfwlist dst -j REDIRECT --to-ports "${local_port}"
	elif [ "${ss_mode}" = "bypass" ]; then
		iptables -w -t nat -A SHADOWSOCKS -p tcp -m set --match-set black_list dst -j REDIRECT --to-ports "${local_port}"
		iptables -w -t nat -A SHADOWSOCKS -p tcp -m set ! --match-set bypass dst -j REDIRECT --to-ports "${local_port}"
	elif [ "${ss_mode}" = "global" ]; then
		iptables -w -t nat -A SHADOWSOCKS -p tcp -j REDIRECT --to-ports "${local_port}"
	elif [ "${ss_mode}" = "gamemode" ]; then
		iptables -w -t nat -A SHADOWSOCKS -p tcp -m set --match-set black_list dst -j REDIRECT --to-ports "${local_port}"
		iptables -w -t nat -A SHADOWSOCKS -p tcp -m set ! --match-set bypass dst -j REDIRECT --to-ports "${local_port}"

		#UDP Rules
		ip rule add fwmark 0x07 table 310 pref 789
		ip route add local default dev lo table 310
		iptables -w -t mangle -N SHADOWSOCKS
		iptables -w -t mangle -A SHADOWSOCKS -p udp -m set --match-set white_list dst -j RETURN
		iptables -w -t mangle -A SHADOWSOCKS -p udp -m set --match-set black_list dst -j TPROXY --on-port "${local_port}" --tproxy-mark 0x07
		iptables -w -t mangle -A SHADOWSOCKS -p udp -m set ! --match-set bypass dst -j TPROXY --on-port "${local_port}" --tproxy-mark 0x07

		iptables -w -t mangle -N SS_MARK
		iptables -w -t mangle -A SS_MARK -p udp -j RETURN -m set --match-set white_list dst
		iptables -w -t mangle -A SS_MARK -p udp -m set --match-set black_list dst -j MARK --set-mark 0x07
		iptables -w -t mangle -A SS_MARK -p udp -m set ! --match-set bypass dst -j MARK --set-mark 0x07

	else
		echo "Wrong proxy mode!" && exit 1
	fi

	#PREROUTING

	# dns_redir
	[ -n "${lanip}" ] && iptables -w -t nat -I PREROUTING -s ${lanip}/24 -p udp --dport 53 -m comment --comment "dns_redir" -j DNAT --to ${lanip}
	# forward
	iptables -w -t nat -I PREROUTING 1 -p tcp -j SHADOWSOCKS
	iptables -w -t nat -I OUTPUT 1 -p tcp -j SHADOWSOCKS

	if [ "${ss_mode}" = "gamemode" ]; then
		iptables -w -t mangle -I PREROUTING 1 -j SHADOWSOCKS
		iptables -w -t mangle -I OUTPUT 1 -j SS_MARK
		if [ "${working_mode}" = "v2ray" ]; then
			echo -e "\e[93mWarning: udp relay may not work with v2ray's dokodemo-door.\e[0m"
		fi
	fi

}

stop_service() {
	echo "Stopping process..."

	if [ "${working_mode}" = "ss" ]; then
		systemctl stop "sslocal-rust@${ss_config}"
	elif [ "${working_mode}" = "v2ray" ]; then
		systemctl stop v2ray@"${ss_config}"
	fi
}

flush_nat() {

	echo "Clear rules..."
	# flush shadowsocks rules
	eval "$(iptables -w -t nat -S | grep SHADOWSOCKS | sed 1d | sed -e "s/-A/iptables -w -t nat -D/")"
	iptables -w -t nat -D PREROUTING -p tcp -j SHADOWSOCKS &>/dev/null
	iptables -w -t mangle -D OUTPUT -j SS_MARK &>/dev/null
	iptables -w -t nat -F SHADOWSOCKS >/dev/null 2>&1 && iptables -w -t nat -X SHADOWSOCKS >/dev/null 2>&1
	eval "$(iptables -w -t mangle -S | grep SHADOWSOCKS | sed 1d | sed -e "s/-A/iptables -w -t mangle -D/")"
	iptables -w -t mangle -D PREROUTING -j SHADOWSOCKS &>/dev/null
	iptables -w -t mangle -F SHADOWSOCKS &>/dev/null && iptables -w -t mangle -X SHADOWSOCKS &>/dev/null
	iptables -w -t mangle -F SS_MARK &>/dev/null && iptables -w -t mangle -X SS_MARK &>/dev/null
	iptables -w -t nat -D OUTPUT -p tcp -j SHADOWSOCKS &>/dev/null
	# flush dns_redir rule
	eval "$(iptables -w -t nat -S | grep "dns_redir" | head -1 | sed -e "s/-A/iptables -w -t nat -D/")" &>/dev/null
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

	# remove generated config
	rm -f "${smartdns_config_dir}"/archwrt-ss.*.conf

  config_smartdns
}

restart_smartdns() {
	# Restart smartdns
	echo "Restarting smartdns..."
	systemctl restart smartdns
}

stop_smartdns() {
	# Stop smartdns
	echo "Stopping smartdns..."
	systemctl stop smartdns
}

check_status() {
	echo '----------- status --------------'
	if [ "${working_mode}" = "ss" ]; then
		systemctl status --no-pager "sslocal-rust@${ss_config}"
	elif [ "${working_mode}" = "v2ray" ]; then
		systemctl status --no-pager v2ray@"${ss_config}"
	fi
	echo '---------------------------------'
	systemctl status --no-pager smartdns.service
	echo '---------------------------------'
	echo "working_mode: ${working_mode}"
	iptables -w -t nat -S | grep -q SHADOWSOCKS && echo "NAT rules added with [${ss_mode}]." || echo "No NAT rules added."
	iptables -w -t mangle -S | grep -q SHADOWSOCKS && echo "UDP rules added." || echo "No UDP rules added."
}

stop() {
	env_check
	stop_service
	flush_nat
	restart_smartdns
	rm /var/run/archwrt-ss.sh.running &> /dev/null
}

start() {
	env_check
    if [[ -f "/var/run/archwrt-ss.sh.running" ]]; then
        echo "Already started and running!"
        echo "If not, try \`rm /var/run/archwrt-ss.sh.running\`"
        exit 0
    fi
	echo "Working Mode: [${working_mode}]"
	prepare "$@"
	echo "Proxy Mode: [${ss_mode}]"
	start_ss_redir
	update_rules
	config_ipset
	create_nat_rules
	if [ "${puredns_managed}" = "true" ]; then
		start_puredns
	fi
	restart_smartdns
	touch /var/run/archwrt-ss.sh.running
}

quick_restart_available(){
	if [[ -f "/var/run/archwrt-ss.sh.running" ]] && \
		[[ ! "$@" =~ (gfwlist)|(bypass)|(gamemode)|(global)|(^$) ]]; then
		return 0
	else
		return 1
	fi
}

quick_restart() {
	env_check
	stop_service
	prepare "$@"
	ipset -! add white_list "${ss_server_ip}" &>/dev/null
	start_ss_redir
	echo "Proxy Mode: [${ss_mode}] (not changed)"
	echo "Switched to ${ss_config}"
}

case "$1" in
start)
	shift
	start "$@"
	;;
stop) stop ;;
restart)
	shift
	if quick_restart_available "$@"; then
		echo "Proxy mode is not changed, restarting quickly..."
		quick_restart "$@"
	else
		echo "Proxy mode is changed or archwrt-ss.sh is not running,"
		echo "Restarting normally..."
		stop
		sleep 1
		start "$@"
	fi
	;;
status) check_status ;;
update) update_rules "f" ;;
*) help ;;
esac

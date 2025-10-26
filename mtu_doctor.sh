#!/bin/sh
# ====================================================
# MTU Doctor for GL.iNet Routers
# Author: phantasm22
# License: GPL-3.0
# Version: 2025-10-25
#
# This script optimizes and manages MTU settings on GL.iNet routers, ensuring
# reliable network and VPN performance. It provides tools to detect optimal MTU
# values, display interface settings, and diagnose network connectivity with
# support for OpenVPN and WireGuard interfaces (server and client).
#
# It supports:
# - Detecting optimal MTU for WAN, WireGuard, OpenVPN server, and VPN clients
# - Checking for active VPN clients before MTU detection
# - Displaying current MTU settings with optional full interface list
# - Comprehensive network diagnostics with link speed and VPN status
# - Updating MTU settings in runtime and GL.iNet web UI (UCI)
# - Setting custom MTU values for specific interfaces, including VLANs
# - BusyBox-compatible operation for GL.iNet routers
# ====================================================

# -----------------------------
# Color & Splash
# -----------------------------
RESET="\033[0m"
CYAN="\033[96m"      # Bright cyan for headers and MTU
GREEN="\033[1;92m"   # Bright green for UP status and success
RED="\033[31m"       # Red for DOWN status and errors
YELLOW="\033[33m"    # Yellow for Speed and IPs
MAGENTA="\033[1;35m" # Bright magenta for emphasis

SPLASH="
   _____ _          _ _   _      _   
  / ____| |        (_) \\ | |    | |  
 | |  __| |  ______ _|  \\| | ___| |_ 
 | | |_ | | |______| | . \` |/ _ \\ __|
 | |__| | |____    | | |\\  |  __/ |_ 
  \\_____|______|   |_|_| \\_|\\___|\\__|

         MTU Doctor for GL.iNet
"

# Cleanup function for Ctrl+C or termination
cleanup() {
    rm -f "/tmp/ping_result_$$" 2>/dev/null
    exit 0
}

# Trap SIGINT and SIGTERM to ensure cleanup
trap cleanup INT TERM

# Interface discovery (GL.iNet-specific)
WAN_IF=$(ip route | grep default | awk '{print $5}' | head -n 1)
WG_IF=$(ip link show | grep -o 'wgserver' || echo 'wgserver')
OVPN_IF=$(ip link show | grep -o 'ovpnserver' || echo 'ovpnserver')

# Helpers
get_mtu() { ip link show "$1" 2>/dev/null | grep -w mtu | awk '{print $5}'; }
get_state() { ip link show "$1" 2>/dev/null | grep -q "UP" && echo "UP" || echo "DOWN"; }
get_speed() {
    IFACE="$1"
    case "$IFACE" in
        eth*|br-lan)
            if [ -f "/sys/class/net/$IFACE/speed" ]; then
                SPEED=$(cat "/sys/class/net/$IFACE/speed" 2>/dev/null)
                [ -n "$SPEED" ] && echo "${SPEED}Mbit/s" || echo "Unknown"
            else
                echo "Unknown"
            fi
            ;;
        *) echo "N/A" ;;
    esac
}

# Return the first usable client address (network.2) for a given interface
vpn_start_ip() {
    local iface=$1
    local ip_addr addr mask bits a b c d
    local network netmask n1 n2 n3

    # Get IP/mask from interface
    ip_addr=$(ip -4 addr show dev "$iface" 2>/dev/null | awk '/inet / {print $2}' | head -n1)
    [ -z "$ip_addr" ] && return 1

    addr=$(echo "$ip_addr" | cut -d'/' -f1)
    mask=$(echo "$ip_addr" | cut -d'/' -f2)
    bits=$(( 32 - mask ))

    # Parse IP octets using cut (no read <<<)
    a=$(echo "$addr" | cut -d. -f1)
    b=$(echo "$addr" | cut -d. -f2)
    c=$(echo "$addr" | cut -d. -f3)
    d=$(echo "$addr" | cut -d. -f4)

    # Convert to 32-bit int
    network=$(( a << 24 | b << 16 | c << 8 | d ))

    # Build netmask
    netmask=0
    i=0
    while [ $i -lt $mask ]; do
        netmask=$(( netmask | (1 << (31 - i)) ))
        i=$((i + 1))
    done

    # Apply netmask
    network=$(( network & netmask ))

    # Extract network octets
    n1=$(( (network >> 24) & 255 ))
    n2=$(( (network >> 16) & 255 ))
    n3=$(( (network >>  8) & 255 ))

    # Return network.2
    printf "%d.%d.%d.2\n" "$n1" "$n2" "$n3"
}

# Function to get max IP from subnet
get_subnet_range() {
    local vpn_type=$1
    local start_ip=$2
    local max_ip=""
    if [ "$vpn_type" = "openvpn" ]; then
        subnet=$(uci get ovpnserver.vpn.server 2>/dev/null | cut -d' ' -f1)
        max_clients=$(uci get ovpnserver.vpn.max-clients 2>/dev/null)
        if [ -n "$subnet" ]; then
            max_ip=$(echo "$subnet" | awk -F'[./]' '{print $1"."$2"."$3"."$4+255-$4}')
            if [ -n "$max_clients" ]; then
                max_num=$(( $(echo "$start_ip" | cut -d'.' -f4) + $max_clients - 1 ))
                max_ip=$(echo "$start_ip" | cut -d'.' -f1-3)".$max_num"
            fi
        else
            max_ip=$(echo "$start_ip" | cut -d'.' -f1-3)".254"
        fi
    elif [ "$vpn_type" = "wireguard" ]; then
        subnet=$(uci show network | grep -E 'addresses.*10.1.0.' | grep -o '10.1.0.[0-9]+/[0-9]+' | head -n 1)
        if [ -n "$subnet" ]; then
            mask=$(echo "$subnet" | cut -d'/' -f2)
            if [ "$mask" = "24" ]; then
                max_ip=$(echo "$start_ip" | cut -d'.' -f1-3)".254"
            else
                max_num=$(( $(echo "$start_ip" | cut -d'.' -f4) + (1 << (32 - $mask)) - 2 ))
                max_ip=$(echo "$start_ip" | cut -d'.' -f1-3)".$max_num"
            fi
        else
            max_ip=$(echo "$start_ip" | cut -d'.' -f1-3)".254"
        fi
    fi
    echo "$max_ip"
}

# Function to detect active VPN client
detect_vpn_client() {
    local interface=$1
    local start_ip=$2
    local vpn_type=$3
    local quiet=$4
    local subnet_prefix=$(echo "$start_ip" | cut -d'.' -f1-3)
    local max_ip=$(get_subnet_range "$vpn_type" "$start_ip")
    local max_num=$(echo "$max_ip" | cut -d'.' -f4)
    local active_ip=""
    local tmpfile="/tmp/ping_result_$$"

    # Check if interface is routable
    if ! ip route show dev "$interface" >/dev/null 2>&1; then
        [ "$quiet" != "yes" ] && printf "${YELLOW}%s not routable. Using default IP: %s${RESET}\n" "$interface" "$start_ip" >&2
        echo "$start_ip:unresponsive"
        return
    fi

    rm -f "$tmpfile"

    # Serially ping first 10 IPs (2-11)
    [ "$quiet" != "yes" ] && printf "${MAGENTA}Scanning for active %s client (.2-.11)...${RESET}\n" "$vpn_type" >&2
    for i in $(seq 2 11); do
        ip="$subnet_prefix.$i"
        if ping -I "$interface" -c 1 -W 1 -s 949 "$ip" >/dev/null 2>&1; then
            active_ip="$ip"
            break
        fi
    done

    # If no response, ping remaining IPs in parallel
    if [ -z "$active_ip" ]; then
        [ "$quiet" != "yes" ] && printf "${MAGENTA}No client found in .2-.11, scanning .12-.%d...${RESET}\n" "$max_num" >&2
        for i in $(seq 12 "$max_num"); do
            ip="$subnet_prefix.$i"
            ping -I "$interface" -c 1 -W 1 -s 949 "$ip" >/dev/null 2>&1 && echo "$ip" >> "$tmpfile" &
        done
        wait
        if [ -s "$tmpfile" ]; then
            active_ip=$(head -n 1 "$tmpfile")
        fi
    fi

    rm -f "$tmpfile" 2>/dev/null

    if [ -n "$active_ip" ]; then
        echo "$active_ip"
    else
        [ "$quiet" != "yes" ] && printf "${YELLOW}No %s client found${RESET}\n" "$vpn_type" >&2
        echo "$start_ip:unresponsive"
    fi
}

detect_vpn_peer_ip() {
    local iface="$1"
    local route_line
    local local_ip
    local peer_ip

    route_line=$(ip route show dev "$iface" proto kernel scope link 2>/dev/null | head -1)
    [ -z "$route_line" ] && return 1

    local_ip=$(echo "$route_line" | grep -o 'src [0-9.]*' | awk '{print $2}')
    [ -z "$local_ip" ] && return 1

    peer_ip="${local_ip%.*}.1"

    ping -c 1 -W 1 -I "$iface" "$peer_ip" >/dev/null 2>&1 && echo "$peer_ip" || return 1
}

test_mtu_vpn() {
    local interface="$1"
    local target_ip="$2"
    local orig_mtu
    local highest_mtu=0
    local max_mtu=1500

    orig_mtu=$(get_mtu "$interface")
    [ -z "$orig_mtu" ] && orig_mtu=1400

    printf "${MAGENTA}Testing max network MTU to %s...${RESET}\n" "$target_ip" >&2

    # Temp raise to 1500
    ip link set "$interface" mtu 1500 2>/dev/null || true

    # Install hping3 if needed
    if ! command -v hping3 >/dev/null 2>&1; then
        printf "${YELLOW}Installing hping3...${RESET}\n" >&2
        opkg update >/dev/null 2>& 1 && opkg install hping3 >/dev/null 2>&1 || {
            ip link set "$interface" mtu "$orig_mtu" 2>/dev/null
            echo "$orig_mtu"
            return
        }
    fi

    # Binary search — CORRECT: le
    local low=1280 high=$max_mtu mid
    while [ $low -le $high ]; do
        mid=$(( (low + high) / 2 ))
        payload=$(( mid - 28 ))
        if hping3 -1 -M 0 -c 1 --data $payload -I "$interface" "$target_ip" 2>/dev/null | grep -q "len=$mid"; then
            highest_mtu=$mid
            low=$(( mid + 1 ))
        else
            high=$(( mid - 1 ))
        fi
    done

    # Restore original MTU
    ip link set "$interface" mtu "$orig_mtu" 2>/dev/null

    [ $highest_mtu -eq 0 ] && highest_mtu=$orig_mtu
    echo "$highest_mtu"
}

# list_interfaces: Displays network interfaces with their status, MTU, and optionally speed,
# or a numbered list for manual selection. Supports filtering for specific interfaces
# (eth*, br-lan, ovpnserver, wgserver) and excluding loopback (lo).
list_interfaces() {
    SHOW_SPEED="$1"
    FILTER="$2"
    FILTER_LO="$3"
    NUMBERED="$4"
    INTERFACES=""
    COUNT=0
    printf "${CYAN}Interfaces and MTUs:${RESET}\n"
    for IF in $(ls /sys/class/net); do
        [ -z "$(ip link show "$IF" 2>/dev/null)" ] && continue
        if [ "$FILTER" = "yes" ]; then
            case "$IF" in
                eth*|br-lan|ovpnserver|wgserver) ;;
                *) continue ;;
            esac
        fi
        [ "$FILTER_LO" = "yes" ] && [ "$IF" = "lo" ] && continue
        COUNT=$((COUNT + 1))
        INTERFACES="$INTERFACES $IF"
        if [ "$NUMBERED" = "yes" ]; then
            printf "  %d) %s\n" "$COUNT" "$IF"
        else
            STATE=$(get_state "$IF")
            MTU=$(get_mtu "$IF")
            SPEED=$(get_speed "$IF")
            STATE_COLOR=$( [ "$STATE" = "UP" ] && echo "${GREEN}UP${RESET}" || echo "${RED}DOWN${RESET}" )
            MTU_COLOR="${CYAN}${MTU:-unknown}${RESET}"
            SPEED_COLOR="${YELLOW}${SPEED:-Unknown}${RESET}"
            if [ "$SHOW_SPEED" = "yes" ]; then
                printf "  • %-10s (%b) - MTU: %b, Speed: %b\n" "$IF" "$STATE_COLOR" "$MTU_COLOR" "$SPEED_COLOR"
            else
                printf "  • %-10s (%b) - MTU: %b\n" "$IF" "$STATE_COLOR" "$MTU_COLOR"
            fi
        fi
    done
}

# apply_mtu: Sets MTU for an interface, updating runtime and UCI for GL.iNet web UI.
apply_mtu() {
    IFACE="$1"; VALUE="$2"
    
    if ip link set "$IFACE" mtu "$VALUE" 2>/dev/null; then
        printf "${GREEN}🎯 MTU on %s set to %s${RESET}\n" "$IFACE" "$VALUE"
    else
        printf "${RED}Failed to set MTU on %s to %s${RESET}\n" "$IFACE" "$VALUE"
        return
    fi
    
    case "$IFACE" in
        ovpnserver)
            uci set ovpnserver.global.mtu="$VALUE"
            uci commit ovpnserver
            /etc/init.d/openvpn restart 2>/dev/null
            ;;
        wgserver)
            uci set wireguard_server.main_server.mtu="$VALUE"
            uci commit wireguard_server
            ifdown "$IFACE" 2>/dev/null
            ifup "$IFACE" 2>/dev/null
            ;;
        wg0)
            uci set wireguard_client."$IFACE".mtu="$VALUE" 2>/dev/null || printf "${YELLOW}No UCI mapping for %s, MTU set at runtime only${RESET}\n" "$IFACE"
            uci commit wireguard_client
            /etc/init.d/wireguard restart 2>/dev/null
            ;;
        tun0)
            uci set ovpnclient.global.mtu="$VALUE" 2>/dev/null || printf "${YELLOW}No UCI mapping for %s, MTU set at runtime only${RESET}\n" "$IFACE"
            uci commit ovpnclient
            /etc/init.d/openvpn restart 2>/dev/null
            ;;
        *)
            if echo "$IFACE" | grep -q "\."; then
                UCI_SECTION=$(uci show network | grep "ifname=.*$IFACE" | cut -d'.' -f2)
                if [ -n "$UCI_SECTION" ]; then
                    uci set network."$UCI_SECTION".mtu="$VALUE"
                    uci commit network
                    ifdown "$UCI_SECTION" 2>/dev/null
                    ifup "$UCI_SECTION" 2>/dev/null
                else
                    printf "${YELLOW}No UCI mapping found for %s, MTU set at runtime only${RESET}\n" "$IFACE"
                fi
            else
                uci set network."$IFACE".mtu="$VALUE" 2>/dev/null
                if [ $? -eq 0 ]; then
                    uci commit network
                    ifdown "$IFACE" 2>/dev/null
                    ifup "$IFACE" 2>/dev/null
                else
                    printf "${YELLOW}No UCI mapping for %s, MTU set at runtime only${RESET}\n" "$IFACE"
                fi
            fi
            ;;
    esac
    
    sleep 2
    ACTUAL=$(get_mtu "$IFACE")
    for i in 1 2 3 4 5; do
        [ -n "$ACTUAL" ] && break
        sleep 2
        ACTUAL=$(get_mtu "$IFACE")
    done
}

# detect_vpn_client_mtu: Checks if router is acting as a VPN client, sources MTU, performs detection via tunnel, and applies if confirmed.
detect_vpn_client_mtu() {
    printf "\n${CYAN}--- Detect VPN Client MTU ---${RESET}\n"
    
    # === Find active client ===
    WG_CLIENT_IF=""
    for iface in $(ls /sys/class/net 2>/dev/null | grep '^wg[0-9]*$'); do
        if [ -d "/sys/class/net/$iface" ] && ip link show "$iface" | grep -q "UP" && command -v wg >/dev/null 2>&1 && wg show "$iface" | grep -q "latest handshake"; then
            WG_CLIENT_IF="$iface"
            break
        fi
    done

    OVPN_CLIENT_IF=""
    for iface in $(ls /sys/class/net 2>/dev/null | grep '^ovpnclient[0-9]*$'); do
        if [ -d "/sys/class/net/$iface" ] && ip link show "$iface" | grep -q "UP"; then
            PEER=$(detect_vpn_peer_ip "$iface")
            if [ -n "$PEER" ] && ping -I "$iface" -c 1 -W 2 "$PEER" >/dev/null 2>&1; then
                OVPN_CLIENT_IF="$iface"
                break
            fi
        fi
    done

    if [ -z "$OVPN_CLIENT_IF" ] && [ -z "$WG_CLIENT_IF" ]; then
        printf "${YELLOW}No active VPN client found.${RESET}\n"
        return
    fi

    IFACE="${OVPN_CLIENT_IF:-$WG_CLIENT_IF}"
    CUR_MTU=$(get_mtu "$IFACE")
    printf "Current MTU: %s\n" "${CUR_MTU:-unknown}"

    PEER_IP=$(detect_vpn_peer_ip "$IFACE")
    if [ -z "$PEER_IP" ]; then
        printf "${RED}Cannot detect peer IP. Skipping.${RESET}\n"
        return
    fi

    RECOMMENDED=$(test_mtu_vpn "$IFACE" "$PEER_IP")

    if [ "$CUR_MTU" = "$RECOMMENDED" ]; then
        printf "${GREEN}Recommended: %d (Already optimal)${RESET}\n" "$RECOMMENDED"
    else
        printf "${YELLOW}Recommended: %d${RESET}\n" "$RECOMMENDED"
        printf "Apply new MTU %d to %s? [y/N]: " "$RECOMMENDED" "$IFACE"
        read ans
        case "$ans" in
            [Yy]*)
                ip link set "$IFACE" mtu "$RECOMMENDED"
                printf "${GREEN}🎯 MTU on %s set to %d${RESET}\n" "$IFACE" "$RECOMMENDED"
                ;;
            *) printf "Skipped.\n" ;;
        esac
    fi
}

detect_ip() { ip -4 addr show "$1" 2>/dev/null | grep inet | awk '{print $2}' | cut -d'/' -f1; }

PUB_IP_CACHE=""
external_ip() {
    [ -n "$PUB_IP_CACHE" ] && { echo "$PUB_IP_CACHE"; return; }
    if command -v wget >/dev/null 2>&1; then
        PUB_IP_CACHE=$(wget -qO- https://api.ipify.org 2>/dev/null)
    elif command -v curl >/dev/null 2>&1; then
        PUB_IP_CACHE=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null)
    else
        PUB_IP_CACHE="Unavailable"
    fi
    echo "$PUB_IP_CACHE"
}

# Diagnostics
run_diagnostics() {
    printf "\n${CYAN}--- Network Diagnostics ---${RESET}\n\n"
    printf "${CYAN}Default route:${RESET}\n"
    ip route show default || printf "(none)\n"
    printf "\n"
    list_interfaces "yes" "yes" "yes"
    printf "\n"
    LAN_IP=$(detect_ip br-lan); WAN_IP=$(detect_ip "$WAN_IF")
    OVPN_IP=$(detect_ip ovpnserver); WG_IP=$(detect_ip wgserver)
    PUB_IP=$(external_ip)
    printf "LAN IP:               ${YELLOW}%s${RESET}\n" "${LAN_IP:-Unavailable}"
    printf "WAN IP:               ${YELLOW}%s${RESET}\n" "${WAN_IP:-Unavailable}"
    printf "OpenVPN Server IP:    ${YELLOW}%s${RESET}\n" "${OVPN_IP:-Inactive}"
    printf "WireGuard Server IP:  ${YELLOW}%s${RESET}\n" "${WG_IP:-Inactive}"
    printf "Public IP:            ${YELLOW}%s${RESET}\n" "${PUB_IP:-Unavailable}"
    printf "\n${CYAN}VPN Server Status:${RESET}\n"

    # WireGuard
    if command -v wg >/dev/null 2>&1; then
        START_IP=$(vpn_start_ip "$WG_IF") || START_IP="10.0.0.2"
        WG_CLIENT_IP=$(detect_vpn_client "$WG_IF" "$START_IP" "wireguard" "yes")
        if echo "$WG_CLIENT_IP" | grep -q ":unresponsive"; then
            printf "${YELLOW}WireGuard server: No active clients${RESET}\n"
        else
            # Tunnel-aware: handshake check optional, ping is definitive
            if ping -I "$WG_IF" -c 1 -W 2 -s 949 "$WG_CLIENT_IP" >/dev/null 2>&1; then
                printf "${GREEN}WireGuard server: Active (client %s)${RESET}\n" "$WG_CLIENT_IP"
            else
                printf "${YELLOW}WireGuard server: Client %s (unreachable via tunnel)${RESET}\n" "$WG_CLIENT_IP"
            fi
        fi
    else
        printf "${YELLOW}WireGuard server: Not installed${RESET}\n"
    fi

    # OpenVPN
    if [ -f /var/run/openvpn-server.status ] && grep -q "CLIENT_LIST" /var/run/openvpn-server.status; then
        START_IP=$(vpn_start_ip "$OVPN_IF") || START_IP="10.0.0.2"
        OVPN_CLIENT_IP=$(detect_vpn_client "$OVPN_IF" "$START_IP" "openvpn" "yes")
        if echo "$OVPN_CLIENT_IP" | grep -q ":unresponsive"; then
            printf "${YELLOW}OpenVPN server: No active clients${RESET}\n"
        else
            printf "${GREEN}OpenVPN server: Active (client %s)${RESET}\n" "$OVPN_CLIENT_IP"
        fi
    else
        printf "${YELLOW}OpenVPN server: No active clients${RESET}\n"
    fi
}

# set_manual_mtu: Allows user to manually set MTU for a selected network interface.
set_manual_mtu() {
    printf "\n${CYAN}--- Set Manual MTU ---${RESET}\n"
    list_interfaces "no" "yes" "no" "yes"
    INTERFACES=$(echo "$INTERFACES" | sed 's/^ *//;s/ *$//')
    COUNT=$(echo "$INTERFACES" | wc -w)
    [ "$COUNT" -eq 0 ] && { printf "${RED}No valid interfaces found${RESET}\n"; return; }
    printf "\nSelect an interface or 'a' to see all interfaces (1-%d, a): " "$COUNT"
    read CHOICE
    if [ "$CHOICE" = "a" ] || [ "$CHOICE" = "A" ]; then
        printf "\n${CYAN}All Interfaces:${RESET}\n"
        list_interfaces "no" "" "" "yes"
        INTERFACES=$(echo "$INTERFACES" | sed 's/^ *//;s/ *$//')
        COUNT=$(echo "$INTERFACES" | wc -w)
        [ "$COUNT" -eq 0 ] && { printf "${RED}No valid interfaces found${RESET}\n"; return; }
        printf "\nSelect an interface (1-%d): " "$COUNT"
        read CHOICE
    fi
    if ! echo "$CHOICE" | grep -qE '^[0-9]+$' || [ "$CHOICE" -lt 1 ] || [ "$CHOICE" -gt "$COUNT" ]; then
        printf "${RED}Invalid interface selection${RESET}\n"
        return
    fi
    IFACE=$(echo "$INTERFACES" | awk "{print \$${CHOICE}}")
    [ -z "$IFACE" ] && { printf "${RED}Error selecting interface${RESET}\n"; return; }
    printf "Enter MTU value (1280-1500): "
    read MTU
    if [ -n "$MTU" ] && echo "$MTU" | grep -qE '^[0-9]+$' && [ "$MTU" -ge 1280 ] && [ "$MTU" -le 1500 ]; then
        apply_mtu "$IFACE" "$MTU"
    else
        printf "${RED}Invalid MTU value (must be 1280-1500)${RESET}\n"
    fi
}

# detect_mtu: Detects optimal MTU for WAN, WireGuard server, or OpenVPN server.
detect_mtu() {
    MODE="$1"
    case "$MODE" in
        wan)
            IFACE="$WAN_IF"
            NAME="WAN"
            ;;
        wireguard)
            IFACE="$WG_IF"
            NAME="WireGuard Server"
            ;;
        openvpn)
            IFACE="$OVPN_IF"
            NAME="OpenVPN Server"
            ;;
        *)
            printf "${RED}Error: invalid mode '%s'${RESET}\n" "$MODE"
            return 1
            ;;
    esac

    if [ -z "$IFACE" ] || ! ip link show "$IFACE" >/dev/null 2>&1; then
        printf "${YELLOW}Interface for %s not found.${RESET}\n" "$NAME"
        return 1
    fi

    printf "\n${CYAN}--- Detect MTU for %s ---${RESET}\n" "$NAME"
    CUR_MTU=$(get_mtu "$IFACE")
    printf "Current MTU: %s\n" "${CUR_MTU:-unknown}"

    if [ "$MODE" = "wan" ]; then
        printf "Testing WAN MTU to 8.8.8.8...\n"
        MIN=1280; MAX=1500; STEP=4; LAST_GOOD=$MIN
        for SIZE in $(seq $MIN $STEP $MAX); do
            ping -I "$IFACE" -c 1 -s $((SIZE - 28)) 8.8.8.8 >/dev/null 2>&1 && LAST_GOOD=$SIZE || break
        done
        RECOMMENDED=$LAST_GOOD
    else
        START_IP=$(vpn_start_ip "$IFACE") || START_IP="10.0.0.2"
        printf "Scanning for client..."
        CLIENT_IP=$(detect_vpn_client "$IFACE" "$START_IP" "$MODE" "yes")
        if echo "$CLIENT_IP" | grep -q ":unresponsive"; then
            printf " none found\n"
            RECOMMENDED=1420
        else
            printf " found %s\n" "$CLIENT_IP"
            RAW_MTU=$(test_mtu_vpn "$IFACE" "$CLIENT_IP")
            RECOMMENDED=$RAW_MTU
            [ $RECOMMENDED -lt 1280 ] && RECOMMENDED=1280
        fi
    fi

    if [ "$CUR_MTU" = "$RECOMMENDED" ]; then
        printf "${GREEN}Recommended: %d (Already optimal)${RESET}\n" "$RECOMMENDED"
    else
        printf "${YELLOW}Recommended: %d${RESET}\n" "$RECOMMENDED"
        printf "Apply new MTU %d to %s? [y/N]: " "$RECOMMENDED" "$IFACE"
        read ans
        case "$ans" in [Yy]*) apply_mtu "$IFACE" "$RECOMMENDED" ;; *) printf "Skipped.\n" ;; esac
    fi
}

# Menu
while true; do
    clear
    printf "${CYAN}%s${RESET}\n" "$SPLASH"
    printf "${CYAN}┌──────────────────────────────┐${RESET}\n"
    printf "${CYAN}│    🧩 MTU Doctor Utility     │${RESET}\n"
    printf "${CYAN}└──────────────────────────────┘${RESET}\n"
    printf " 1) Show current MTU settings\n"
    printf " 2) Detect optimal MTU (no VPN)\n"
    printf " 3) Detect optimal MTU for WireGuard server\n"
    printf " 4) Detect optimal MTU for OpenVPN server\n"
    printf " 5) Detect optimal MTU for VPN clients\n"
    printf " 6) Run diagnostics\n"
    printf " 7) Set manual MTU\n"
    printf " 8) Exit\n\n"
    printf "Select an option: "; read opt

    case "$opt" in
        1) printf "\n${CYAN}--- Current MTU Settings ---${RESET}\n"
           list_interfaces "no" "yes" "no"
           printf "\nShow all interfaces or press Enter to return to menu: [a/Enter] "
           read ans
           if [ "$ans" = "a" ] || [ "$ans" = "A" ]; then
               printf "\n${CYAN}--- All Interfaces ---${RESET}\n"
               list_interfaces "no" "no" "no"
               printf "\nPress Enter to return to menu... "
               read _
           fi
           ;;
        2) detect_mtu "wan"; printf "\nPress Enter to return to menu..."; read _ ;;
        3) detect_mtu "wireguard"; printf "\nPress Enter to return to menu..."; read _ ;;
        4) detect_mtu "openvpn"; printf "\nPress Enter to return to menu..."; read _ ;;
        5) detect_vpn_client_mtu; printf "\nPress Enter to return to menu..."; read _ ;;
        6) run_diagnostics
           printf "\nShow all interfaces or press Enter to return to menu: [y/enter] "
           read ans
           if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
               printf "\n${CYAN}--- All Interfaces ---${RESET}\n"
               list_interfaces "no" "no" "no"
               printf "\nPress Enter to return to menu... "
               read _
           fi
           ;;
        7) set_manual_mtu; printf "\nPress Enter to return to menu... "; read _ ;;
        8) exit 0 ;;
        *) printf "${YELLOW}Invalid option.${RESET}\n"; sleep 1 ;;
    esac
done

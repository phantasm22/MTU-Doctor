# 📡 MTU Doctor

Automated MTU discovery, testing & optimization for WAN, WireGuard, and OpenVPN interfaces on GL.iNet and OpenWrt routers.

---

## ✅ Features

- Detects optimal MTU using binary search + PMTUD (Don't Fragment flag)
- Works with:
  - **WAN (eth0)**
  - **WireGuard Server/Client (wgserver / wgclient)**
  - **OpenVPN Server/Client (ovpnserver / ovpnclient)**
- Automatically accounts for VPN overhead  
  (WireGuard: `-80`, OpenVPN: `-72`)
- Safe apply confirmation + rollback option
- BusyBox + ash compatible (GL.iNet supported)
- No external dependencies required
- Clean terminal UI with spinner + status icons

---

## 📥 Install

~~~sh
wget -O mtu_doctor.sh https://raw.githubusercontent.com/phantasm22/MTU-Doctor/main/mtu_doctor.sh && chmod +x mtu_doctor.sh
~~~

Run:

~~~sh
./mtu_doctor.sh
~~~

---

## 📌 Menu

~~~
📡 MTU Doctor v1.0

1) Detect MTU (WireGuard server)
2) Detect MTU (WAN interface)
3) Detect MTU (WireGuard client)
4) Detect MTU (OpenVPN interface)
5) Restore default MTU values
6) Run diagnostics
7) Set manual MTU
0) Exit
~~~

---

## 🧪 Example Detection Flow

~~~
Detecting MTU via ovpnserver (openvpn mode)...
Current MTU on ovpnserver: 1380
Testing MTU with target: 8.8.8.8
✅ Base path MTU: 1400
ℹ️  Adjusting for OpenVPN overhead (-72) → 1328
Detected MTU differs from current.
Apply new MTU 1328 to ovpnserver? [y/N]:
~~~

---

## ✅ Compatibility

| Platform | Status |
|----------|--------|
| GL.iNet Firmware (Flint, Slate, Beryl, etc.) | ✅ |
| OpenWrt 19+ | ✅ |
| BusyBox + ash | ✅ |
| BCM + Qualcomm Routers | ✅ |

---

## 🤝 Contributing

Issues and PRs welcome!

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**  
See: https://www.gnu.org/licenses/gpl-3.0.html


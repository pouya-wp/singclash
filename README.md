<div align="center">

# ⚡ SingClash

### High-Performance sing-box to Clash.Meta / Mihomo Profile Middleware

[![Platform](https://img.shields.io/badge/Platform-Node.js%20%7C%20Vercel%20Serverless-black?style=flat-square&logo=vercel)](https://vercel.com)
[![JavaScript](https://img.shields.io/badge/Node.js-ES%20Modules-339933?style=flat-square&logo=nodedotjs)](https://nodejs.org/)
[![Database](https://img.shields.io/badge/Storage-Upstash%20Redis-FF4438?style=flat-square&logo=redis)](https://upstash.com/)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/Author-Pouya%20Sadeghpour-181717?style=flat-square&logo=github)](https://github.com/pouya-wp)

<p align="center">
  <b>SingClash</b> bridges the gap between sing-box subscriptions and Clash.Meta / Mihomo clients (FlClash). It transforms raw JSON outbounds into optimized YAML proxy groups with automatic ping URL-test sorting, quota header propagation, and a clean configuration panel.
</p>

</div>

---

## ✨ Features

- 🔄 **Real-Time Protocol Translation** — Seamlessly converts VLESS (Reality & Vision), VMess, Trojan, Shadowsocks (ShadowTLS / Obfs), Hysteria 1 & 2, TUIC, and WireGuard.
- ⚡ **Automated URL-Test Ping Groups** — Dynamically builds auto-failover and latency-tested proxy groups for FlClash.
- 📊 **Bandwidth Quota Pass-Through** — Forwards upstream `subscription-userinfo` headers (data allowance & expiry) directly to client GUI.
- 🛡️ **Fail-Safe 502 Guard** — Returns HTTP 502 if upstream fetches fail to prevent client profiles from being overwritten with empty configs.
- 🎛️ **Dual Storage Mode** — Works locally with `config.json` or in serverless environments via Upstash Redis KV.

---

## 🏗️ Architecture

```
SingClash Architecture
├── HTTP Inbound Gateway (/sub?token=...)
│    ├── Client Identification & Basic Auth Security
│    └── User-Agent Spoofing Pipeline (sing-box mimicry)
├── Parsing & Conversion Engine
│    ├── sing-box JSON AST Parser (Outbounds & Endpoints)
│    ├── Manual URI Parser (vless://, vmess://, hysteria2://, snell)
│    └── Mihomo YAML Serializer (url-test & select groups)
└── Storage Layer (Local JSON or Upstash Redis KV)
```

---

## 🚀 Quick Start

### Local Development

```bash
# Clone the repository
git clone https://github.com/pouya-wp/singclash.git
cd singclash

# Install dependencies and start server
npm install
npm run dev
```

Open `http://localhost:3000` to access the admin panel.

---

## 📄 License

Distributed under the MIT License.

---

<div align="center">
  <sub>Crafted with precision & passion by <b><a href="https://github.com/pouya-wp">Pouya Sadeghpour</a></b></sub>
</div>

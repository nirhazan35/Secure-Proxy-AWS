# 🔐 Secure HTTP Proxy

A minimal, asynchronous HTTP/HTTPS proxy server built with `asyncio`. Supports:

- 🔒 Basic authentication (`Proxy-Authorization: Basic …`)
- 📜 Per-user access control (ACL skeleton)
- 🚫 Domain blocklist (`blocklist.txt`)
- 📄 JSON-line rotating logs
- 🛡️ Optional TLS termination (ready for future MITM support)

---

## 🚀 Quick Start

### 1. Setup

```bash
git clone https://github.com/yourusername/secure-proxy.git
cd secure-proxy
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Environment Variables

Create a `.env` file in the project root and define:

```
PROXY_LISTEN_HOST=0.0.0.0
PROXY_LISTEN_PORT=8080
PROXY_AUTH_ENABLED=true
PROXY_USERS=admin:adminpass,alice:secret,bob:1234
PROXY_BLOCKLIST_PATH=blocklist.txt
```

### 3. Run

```bash
python main.py
```

---

## 🧠 Features

| Feature              | Description                                   |
|----------------------|-----------------------------------------------|
| Authentication       | Basic HTTP Auth per user                      |
| ACL (Skeleton)       | Placeholder for per-user access control       |
| Blocklist            | Blocks domains listed in `blocklist.txt`      |
| Structured Logs      | JSONL logs with rotation                      |
| TLS Ready            | TLS termination support (optional)            |

---

## 🗂 Project Structure

```
secure-proxy/
├── main.py
├── blocklist.txt
├── requirements.txt
├── README.md
└── proxy/
    ├── auth.py
    ├── acls.py
    ├── blocklist.py
    ├── config.py
    ├── core.py
    ├── logger.py
    └── tls.py
```

---

## 🧪 Testing

**Curl:**
```bash
curl -x http://localhost:8080 --proxy-user admin:adminpass http://example.com
```

**Browser:**
- Set proxy to `localhost:8080`
- Use valid credentials when prompted

---

## 📝 Blocklist

Edit `blocklist.txt` to specify blocked domains (supports regex):

```
*.facebook.*
*.gov.*
test.com
```

---

## 🪵 Logging

Logs are saved in `logs.jsonl` in JSON Lines format. Each event includes timestamp, user, IP, method, URL, and status. Example:

```json
{"event":"auth_fail","ts":"2025-06-29T10:30:12Z","ip":"127.0.0.1","user":"admin"}
```

Logged events include:
- Failed login attempts
- Successful authentications
- Allowed requests
- Blocked requests

---

## 🧭 Browser Setup

### Configure Firefox

1. Go to **Settings → General** (scroll down) → click **Settings** under *Network Settings*.
2. Select **Manual proxy configuration**:
   - HTTP Proxy: `localhost`
   - Port: `8080`
   - ✅ Check "Also use this proxy for HTTPS"
   - Click **OK**
3. When accessing a website, you will be prompted for credentials. Enter one of the usernames/passwords set in the `.env` file.
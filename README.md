# Secure HTTP Proxy (Course Project)

A minimal, **asyncio**-based HTTP/HTTPS proxy that supports:

* User authentication (`Proxy-Authorization: Basic …`)
* Per-user ACL skeleton
* Domain block-list (`blocklist.txt`)
* JSON-line rotating logs
* Optional TLS termination (client → proxy) & future MITM hooks

---

## Quick Start

```bash
# 1 – Clone & set up
python -m venv venv && . venv/bin/activate
pip install -r requirements.txt

# 2 – Create users
export PROXY_USERS="alice:secret,bob:1234"

# 3 – Start proxy (listen :8080, plaintext)
python -m secure_http_proxy.main

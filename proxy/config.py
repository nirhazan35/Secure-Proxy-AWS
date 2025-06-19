from dataclasses import dataclass
import os
from dotenv import load_dotenv

@dataclass
class Config:
    listen_host: str
    listen_port: int
    use_tls: bool
    auth_enabled: bool
    blocklist_path: str
    log_path: str

def load_config():
    load_dotenv(override=True)
    return Config(
        listen_host=os.getenv("PROXY_LISTEN_HOST", "0.0.0.0"),
        listen_port=int(os.getenv("PROXY_LISTEN_PORT", 8080)),
        use_tls=os.getenv("PROXY_USE_TLS", "false").lower() == "true",
        auth_enabled=os.getenv("PROXY_AUTH_ENABLED", "false").lower() == "true",
        blocklist_path=os.getenv("PROXY_BLOCKLIST_PATH", "blocklist.txt"),
        log_path=os.getenv("PROXY_LOG_PATH", "proxy.log"),
    )

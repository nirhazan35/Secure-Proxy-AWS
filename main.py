import os
from dotenv import load_dotenv

load_dotenv(override=True)

from proxy.config import load_config
from proxy.core import run_proxy

def main():
    config = load_config()
    run_proxy(config)

if __name__ == "__main__":
    main()

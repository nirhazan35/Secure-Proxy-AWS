from proxy.core import run_proxy
from proxy.config import load_config

def main():
    config = load_config()
    run_proxy(config)

if __name__ == "__main__":
    main()

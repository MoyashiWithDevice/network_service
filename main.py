import argparse
import logging
import signal
import sys
import threading
import time
import json
from network_manager import NetworkManager
from dhcp_server import DHCPServer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("Main")

def signal_handler(sig, frame):
    logger.info("Shutting down...")
    sys.exit(0)

def load_config(config_path):
    # Default config
    config = {
        "bridge_name": "br0",
        "interfaces": ["eth1", "eth2"],
        "bridge_ip": "192.168.10.1/24",
        "dhcp": {
            "subnet": "192.168.10.0/24",
            "range_start": "192.168.10.100",
            "range_end": "192.168.10.200",
            "dns": "8.8.8.8"
        }
    }
    
    try:
        with open(config_path, 'r') as f:
            user_config = json.load(f)
            config.update(user_config)
    except FileNotFoundError:
        logger.warning(f"Config file {config_path} not found, using defaults.")
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        
    return config

def main():
    parser = argparse.ArgumentParser(description="Ubuntu Network Service (Router/Switch/DHCP)")
    parser.add_argument("--config", default="config.json", help="Path to configuration file")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    config = load_config(args.config)
    logger.info(f"Starting with config: {config}")

    # Initialize Network Manager
    nm = NetworkManager()
    
    try:
        # Setup Bridge and Interfaces
        nm.create_bridge(config["bridge_name"], config["interfaces"])
        nm.set_ip(config["bridge_name"], config["bridge_ip"])
        nm.enable_forwarding()
        
        # Start DHCP Server
        dhcp = DHCPServer(
            interface_ip=config["bridge_ip"].split('/')[0],
            subnet=config["dhcp"]["subnet"],
            range_start=config["dhcp"]["range_start"],
            range_end=config["dhcp"]["range_end"],
            dns=config["dhcp"]["dns"]
        )
        
        dhcp_thread = threading.Thread(target=dhcp.start)
        dhcp_thread.daemon = True
        dhcp_thread.start()
        
        logger.info("Service is running. Press Ctrl+C to stop.")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except Exception as e:
        logger.error(f"Fatal error: {e}")
    finally:
        nm.close()

if __name__ == "__main__":
    main()

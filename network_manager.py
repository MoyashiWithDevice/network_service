import logging
import os
from pyroute2 import IPRoute, NDB

logger = logging.getLogger(__name__)

class NetworkManager:
    def __init__(self):
        self.ipr = IPRoute()
        self.ndb = NDB()

    def create_bridge(self, bridge_name, interfaces):
        """
        Creates a bridge and attaches specified interfaces to it.
        """
        try:
            # Check if bridge exists
            links = self.ipr.link_lookup(ifname=bridge_name)
            if not links:
                logger.info(f"Creating bridge: {bridge_name}")
                self.ipr.link("add", ifname=bridge_name, kind="bridge")
            else:
                logger.info(f"Bridge {bridge_name} already exists")

            bridge_idx = self.ipr.link_lookup(ifname=bridge_name)[0]
            
            # Bring bridge up
            self.ipr.link("set", index=bridge_idx, state="up")

            for iface in interfaces:
                logger.info(f"Attaching {iface} to {bridge_name}")
                idx = self.ipr.link_lookup(ifname=iface)
                if not idx:
                    logger.error(f"Interface {iface} not found")
                    continue
                idx = idx[0]
                
                # Set interface master to bridge
                self.ipr.link("set", index=idx, master=bridge_idx)
                # Bring interface up
                self.ipr.link("set", index=idx, state="up")
                
        except Exception as e:
            logger.error(f"Error creating bridge {bridge_name}: {e}")
            raise

    def set_ip(self, iface, ip_cidr):
        """
        Assigns an IP address to an interface (e.g., '192.168.1.1/24').
        """
        try:
            idx = self.ipr.link_lookup(ifname=iface)
            if not idx:
                logger.error(f"Interface {iface} not found for IP assignment")
                return
            idx = idx[0]

            # Check if IP already assigned
            # This is a simplified check. In a real app, we might want to be more robust.
            self.ipr.addr("add", index=idx, address=ip_cidr.split('/')[0], mask=int(ip_cidr.split('/')[1]))
            logger.info(f"Assigned {ip_cidr} to {iface}")
        except Exception as e:
            # Ignore "File exists" error which means IP is already assigned
            if "File exists" not in str(e):
                logger.error(f"Error setting IP on {iface}: {e}")

    def enable_forwarding(self):
        """
        Enables IPv4 forwarding in the kernel.
        """
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')
            logger.info("IPv4 forwarding enabled")
        except Exception as e:
            logger.error(f"Failed to enable IP forwarding: {e}")

    def close(self):
        self.ipr.close()
        self.ndb.close()

import socket
import struct
import logging
import threading
import time
from ipaddress import IPv4Network, IPv4Address

logger = logging.getLogger(__name__)

class LeaseManager:
    def __init__(self, subnet, range_start, range_end, lease_time=3600):
        self.subnet = IPv4Network(subnet)
        self.range_start = IPv4Address(range_start)
        self.range_end = IPv4Address(range_end)
        self.lease_time = lease_time
        self.leases = {} # MAC -> {ip, expiry}
        self.offered = {} # MAC -> {ip, expiry}

    def get_lease(self, mac):
        # Clean up expired leases
        now = time.time()
        # Note: In a real app, we should clean up periodically, not just on access
        
        if mac in self.leases:
            if self.leases[mac]['expiry'] > now:
                return self.leases[mac]['ip']
            else:
                del self.leases[mac]
        return None

    def offer_ip(self, mac):
        existing = self.get_lease(mac)
        if existing:
            return existing

        # Find available IP
        used_ips = {l['ip'] for l in self.leases.values()}
        used_ips.update({o['ip'] for o in self.offered.values() if o['expiry'] > time.time()})

        for ip_int in range(int(self.range_start), int(self.range_end) + 1):
            ip = str(IPv4Address(ip_int))
            if ip not in used_ips:
                self.offered[mac] = {'ip': ip, 'expiry': time.time() + 60} # 1 min to accept offer
                return ip
        return None

    def commit_lease(self, mac, ip):
        self.leases[mac] = {'ip': ip, 'expiry': time.time() + self.lease_time}
        if mac in self.offered:
            del self.offered[mac]
        logger.info(f"Lease committed: {mac} -> {ip}")

class DHCPServer:
    def __init__(self, interface_ip, subnet, range_start, range_end, dns="8.8.8.8"):
        self.server_ip = interface_ip
        self.dns = dns
        self.lease_manager = LeaseManager(subnet, range_start, range_end)
        self.sock = None
        self.running = False

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            self.sock.bind(('0.0.0.0', 67))
        except PermissionError:
            logger.error("Permission denied: Cannot bind to port 67. Run as root.")
            return

        self.running = True
        logger.info("DHCP Server started on port 67")
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                self.handle_packet(data, addr)
            except Exception as e:
                if self.running:
                    logger.error(f"Error receiving packet: {e}")

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

    def handle_packet(self, data, addr):
        # Very basic parsing
        # First 240 bytes are fixed header
        if len(data) < 240:
            return
        
        op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr = struct.unpack('!BBBBIHHIIII16s', data[:28])
        
        # Magic cookie
        if data[236:240] != b'\x63\x82\x53\x63':
            return

        # Parse options
        options = {}
        idx = 240
        while idx < len(data):
            opt_code = data[idx]
            if opt_code == 255: break # End
            if opt_code == 0: 
                idx += 1
                continue
            opt_len = data[idx+1]
            opt_val = data[idx+2:idx+2+opt_len]
            options[opt_code] = opt_val
            idx += 2 + opt_len

        msg_type = options.get(53) # DHCP Message Type
        if not msg_type: return
        msg_type = msg_type[0]

        mac_bytes = chaddr[:6]
        mac_str = ':'.join('%02x' % b for b in mac_bytes)

        if msg_type == 1: # DISCOVER
            logger.info(f"Received DISCOVER from {mac_str}")
            offered_ip = self.lease_manager.offer_ip(mac_str)
            if offered_ip:
                self.send_reply(xid, mac_bytes, offered_ip, 2) # OFFER

        elif msg_type == 3: # REQUEST
            logger.info(f"Received REQUEST from {mac_str}")
            requested_ip_opt = options.get(50)
            if requested_ip_opt:
                requested_ip = socket.inet_ntoa(requested_ip_opt)
                # Verify if this IP was offered or already leased
                # For simplicity, we just commit whatever valid IP they ask for if it matches our offer logic
                # In strict DHCP, we should check server identifier etc.
                self.lease_manager.commit_lease(mac_str, requested_ip)
                self.send_reply(xid, mac_bytes, requested_ip, 5) # ACK

    def send_reply(self, xid, mac_bytes, yiaddr_str, msg_type):
        # Construct packet
        # op=2 (BOOTREPLY), htype=1 (Ethernet), hlen=6, hops=0
        packet = struct.pack('!BBBBIHHIIII16s', 2, 1, 6, 0, xid, 0, 0, 0, 0, 0, 0, 0, mac_bytes + b'\x00'*10)
        
        # Server host name (64s) and file name (128s) - empty
        packet += b'\x00' * 192
        
        # Magic cookie
        packet += b'\x63\x82\x53\x63'

        # Options
        # Message Type
        packet += b'\x35\x01' + bytes([msg_type])
        
        # Subnet Mask
        mask_bytes = socket.inet_aton(str(self.lease_manager.subnet.netmask))
        packet += b'\x01\x04' + mask_bytes
        
        # Router (Gateway)
        router_bytes = socket.inet_aton(self.server_ip)
        packet += b'\x03\x04' + router_bytes
        
        # DNS
        dns_bytes = socket.inet_aton(self.dns)
        packet += b'\x06\x04' + dns_bytes
        
        # Server Identifier
        packet += b'\x36\x04' + socket.inet_aton(self.server_ip)

        # Lease Time
        packet += b'\x33\x04' + struct.pack('!I', self.lease_manager.lease_time)

        # End
        packet += b'\xff'

        # Pad to minimum size if needed (BOOTP min is 300 bytes usually, but DHCP can be smaller)
        
        yiaddr_int = struct.unpack('!I', socket.inet_aton(yiaddr_str))[0]
        # We need to patch yiaddr in the header
        # Re-pack the first part with yiaddr
        header_start = struct.pack('!BBBBIHHIIII', 2, 1, 6, 0, xid, 0, 0, 0, yiaddr_int, 0, 0)
        packet = header_start + packet[28:]

        # Send to broadcast
        try:
            self.sock.sendto(packet, ('255.255.255.255', 68))
            logger.info(f"Sent reply type {msg_type} to {yiaddr_str}")
        except Exception as e:
            logger.error(f"Failed to send reply: {e}")

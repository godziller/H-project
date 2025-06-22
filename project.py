import socket
import struct
import fcntl
import binascii
import time


def get_interface_info(ifname):
    # Create simple UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    ip = socket.inet_ntoa(fcntl.ioctl(
        s.fileno(), 0x8915,
        struct.pack('256s', ifname[:15].encode())               # C structure
    )[20:24])

    mac = fcntl.ioctl(
        s.fileno(), 0x8927,  # SIOCGIFHWADDR
        struct.pack('256s', ifname[:15].encode())
    )[18:24]

    return ip, mac


def build_arp_request(src_ip, src_mac, target_ip):
    dst_mac = b'\xff\xff\xff\xff\xff\xff'  # Broadcast for mac addresses
    eth_type = b'\x08\x06'  # ARP

    eth_header = dst_mac + src_mac + eth_type       # Make header

    htype = b'\x00\x01'  # Ethernet
    ptype = b'\x08\x00'  # IPv4
    hlen = b'\x06'
    plen = b'\x04'
    opcode = b'\x00\x01'  # ARP request

    sender_ip = socket.inet_aton(src_ip)
    target_ip = socket.inet_aton(target_ip)
    target_mac = b'\x00' * 6

    arp_payload = (
        htype + ptype + hlen + plen + opcode +
        src_mac + sender_ip + target_mac + target_ip
    )

    return eth_header + arp_payload


def get_subnet(ip):
    return '.'.join(ip.split('.')[:3]) + '.'


def scan_network(ifname):
    print(f"[i] Using interface: {ifname}")

    src_ip, src_mac = get_interface_info(ifname)
    print(f"[i] Local IP: {src_ip}")
    print(f"[i] Local MAC: {':'.join('%02x' % b for b in src_mac)}\n")

    raw_socket = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    raw_socket.bind((ifname, 0))
    raw_socket.settimeout(2)

    subnet = get_subnet(src_ip)
    print(f'USING SUBNET: {subnet} ')
    # Send ARP requests
    for i in range(1, 255):
        target_ip = subnet + str(i)
        packet = build_arp_request(src_ip, src_mac, target_ip)
        raw_socket.send(packet)

    print("[+] Waiting for ARP replies...\n")
    found = set()

    start_time = time.time()
    while time.time() - start_time < 3:
        try:
            data = raw_socket.recv(65535)
            if data[12:14] == b'\x08\x06' and data[20:22] == b'\x00\x02':  # ARP reply
                sender_mac = ':'.join('%02x' % b for b in data[22:28])
                sender_ip = socket.inet_ntoa(data[28:32])
                if sender_ip not in found:
                    found.add(sender_ip)
                    print(f"[✓] {sender_ip} -> {sender_mac}")
        except socket.timeout:
            break


if __name__ == "__main__":
    scan_network("wlp0s20f3")  # Replace "eth0" with your interface name

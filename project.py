import socket
import struct
import fcntl
import binascii
import time
import sys
import threading
import concurrent.futures
import ipaddress


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
    # get subnet for scan e.g 192.168.1.__
    return '.'.join(ip.split('.')[:3]) + '.'


def scan_network(ifname):

    if len(sys.argv) == 2:

        print(f"[i] Using interface: {ifname}")

        src_ip, src_mac = get_interface_info(ifname)
        print(f"[i] Local IP: {src_ip}")
        print(f"[i] Local MAC: {':'.join('%02x' % b for b in src_mac)}\n")

        # Creation of raw socket with Byte data stream
        raw_socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        raw_socket.bind((ifname, 0))
        raw_socket.settimeout(2)

        subnet = get_subnet(src_ip)
        print(f'USING SUBNET: {subnet} ')

        # Send ARP requests
        # combine subnet with int of possible range
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
    else:
        sys.exit("Usage: 'sudo python3 project.py <command>' ")


def target_init():
    # Validate IP input
    while True:
        target = input("IP of target: ")
        try:
            ipaddress.ip_address(target)
            break
        except ValueError:
            print("Invalid IP address. Please enter a valid IPv4 or IPv6 address.")

    # Maximum amount of TCP ports to scan
    ports_to_scan = range(1, 65536)
    start_time = time.time()  # Clock for timeout exit

    print(f"Starting scan on {target}...\n")

    # Using thread pool to deploy threads for port scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=1000) as executor:
        futures = [executor.submit(targ, target, port)
                   for port in ports_to_scan]
        concurrent.futures.wait(futures)

    duration = time.time() - start_time
    print(f"\nScan completed in {duration:.2f} seconds.")


def targ(target, port):
    # Create simple TCP socket as 's'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        result = s.connect_ex((target, port))  # connect_ex --> int (0 | 1)
        if result == 0:
            print(f"[OPEN] Port {port}")
        return result


if __name__ == "__main__":
    ports_to_scan = range(1, 1025)

    if len(sys.argv) == 2:
        if sys.argv[1] == "scan":
            # Replace "eth0" with your interface name
            scan_network("wlp0s20f3")
        elif sys.argv[1] == "targ":
            target_init()

        else:
            sys.exit("Usage: sudo python3 project.py <scan|targ>")
    else:
        sys.exit("Usage: sudo python3 project.py <scan|targ>")

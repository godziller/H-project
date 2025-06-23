import unittest
from unittest.mock import patch, MagicMock
import socket
import struct
import project


class TestProjectFunctions(unittest.TestCase):

    # These decorators come from unittest.mock and are used to replace real functions or classes with mock objects during a test.
    @patch("project.socket.socket")
    # Prevents actual socket creation during test
    @patch("project.fcntl.ioctl")
    def test_get_interface_info(self, mock_ioctl, mock_socket):
        mock_ioctl.side_effect = [
            b"\x00" * 20 + socket.inet_aton("192.168.1.10") + b"\x00" * 8,
            b"\x00" * 18 + b"\xaa\xbb\xcc\xdd\xee\xff"
        ]
        ip, mac = project.get_interface_info("eth0")
        self.assertEqual(ip, "192.168.1.10")
        self.assertEqual(mac, b"\xaa\xbb\xcc\xdd\xee\xff")

    def test_get_subnet(self):
        self.assertEqual(project.get_subnet("192.168.1.105"), "192.168.1.")

    def test_build_arp_request_length(self):
        src_ip = "192.168.1.10"
        src_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        target_ip = "192.168.1.1"
        packet = project.build_arp_request(src_ip, src_mac, target_ip)
        self.assertEqual(len(packet), 42)  # Ethernet (14) + ARP (28)

    @patch("project.socket.socket")
    def test_targ_open_port(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 0  # Simulate open port
        mock_socket_class.return_value.__enter__.return_value = mock_socket
        result = project.targ("127.0.0.1", 80)
        self.assertEqual(result, 0)

    @patch("project.socket.socket")
    def test_targ_closed_port(self, mock_socket_class):
        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 1  # Simulate closed port
        mock_socket_class.return_value.__enter__.return_value = mock_socket
        result = project.targ("127.0.0.1", 9999)
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()

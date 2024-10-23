import dpkt
import socket
import base64
import binascii

from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import scrypt

_MSG_BUF_SIZE = 1024

class ChannelICMP:
    def __init__(self, src_ip, dest_ip):
        self.src_ip = src_ip
        self.dest_ip = dest_ip

    def send(self, data):
        pkt = dpkt.icmp.ICMP.Echo()
        pkt.id = 3
        pkt.seq = 2
        pkt.data = data

        print(binascii.hexlify(pkt.data, ' '))

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, dpkt.ip.IP_PROTO_ICMP)
        s.connect((self.dest_ip, 1))
        s.send(pkt.pack())

    def recv(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        recvPac, addr = s.recvfrom(_MSG_BUF_SIZE)
        pkt = dpkt.icmp.ICMP.Echo()
        pkt.unpack(recvPac)
        print(binascii.hexlify(pkt.data, b' '))
        print(addr)


c2 = ChannelICMP('127.0.0.1', '127.0.0.1')
#c2.recv()
c2.send(base64.b64encode('hi this is a big amount of data hi this is a big amount of data hi this is a big amount of data hi this is a big amount of data hi this is a big amount of data'.encode()))
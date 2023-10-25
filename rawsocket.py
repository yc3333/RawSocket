import argparse
import sys
import socket
import struct
import time
from urllib import parse
from random import randint
from collections import namedtuple, OrderedDict
from functools import reduce



SYN = 0 + (1 << 1) + (0 << 2) + (0 << 3) + (0 << 4) + (0 << 5)
ACK = 0 + (0 << 1) + (0 << 2) + (0 << 3) + (1 << 4) + (0 << 5)
SYN_ACK = 0 + (1 << 1) + (0 << 2) + (0 << 3) + (1 << 4) + (0 << 5)
FIN = 1 + (0 << 1) + (0 << 2) + (0 << 3) + (0 << 4) + (0 << 5)
FIN_ACK = 1 + (0 << 1) + (0 << 2) + (0 << 3) + (1 << 4) + (0 << 5)
PSH_ACK = 0 + (0 << 1) + (0 << 2) + (1 << 3) + (1 << 4) + (0 << 5)

IP_HDR_FMT = '!BBHHHBBH4s4s'
TCP_HDR_FMT = '!HHLLBBHHH'
PSH_FMT = '!4s4sBBH'
IPDatagram = namedtuple(
    'IPDatagram', 'ip_tlen ip_id ip_frag_off ip_saddr ip_daddr data ip_check')
TCPSeg = namedtuple(
    'TCPSeg', 'tcp_source tcp_dest tcp_seq tcp_ack_seq tcp_check data tcp_flags tcp_adwind')


class MyTCPSocket(object):
    ssocket = None
    rsocket = None
    remote_host = ''
    remote_port = -1
    local_host = ''
    local_port = -1
    send_buf = ''
    recv_buf = ''
    tcp_seq = 0
    tcp_ack_seq = 0
    ip_id = 0
    status = ''
    adwind_size = 4096

    def __init__(self):                              
        self.rsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_TCP)
        self.rsocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) 
        self.local_host = "134.82.163.202" #change to the testing host ip
        self.local_port = self._get_free_port()

    def _get_free_port(self):
        """
        Get a free port number for the client to use as source port.
        """
        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_sock.bind(("", 0))
        port = temp_sock.getsockname()[1]
        temp_sock.close()
        return port

    def checksum(self, data):
        if len(data) % 2 == 1:
            data += b"\0"

        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            checksum += word

        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        checksum = ~checksum & 0xFFFF

        return checksum    


    def pack_ip_datagram(self, payload):
        '''
        Generate IP datagram.
        `payload` is TCP segment
        '''
        ip_ver = 4  # IPv4
        ip_ihl = 5  # 5 * 32 bits = 20 bytes
        ip_dscp = 0
        ip_ecn = 0
        ip_len = 0  # Fill in later
        ip_id = 54321
        ip_flags = 0
        ip_offset = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_chksum = 0  # Fill in later
        ip_saddr = socket.inet_aton(self.local_host)
        ip_daddr = socket.inet_aton(self.remote_host)

        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            (ip_ver << 4) | ip_ihl, ip_dscp | ip_ecn, ip_len, ip_id,
            (ip_flags << 13) | ip_offset, ip_ttl, ip_proto, ip_chksum,
            ip_saddr, ip_daddr
        )
        return ip_header + payload


    def pack_tcp_segment(self, payload=b'', flags=ACK):
        '''
        Generate TCP segment.
        '''

        # tcp header fields
        tcp_source = self.local_port   # source port
        tcp_dest = self.remote_port   # destination port
        tcp_seq = self.tcp_seq
        tcp_ack_seq = self.tcp_ack_seq
        tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
        tcp_window = self.adwind_size  # maximum allowed window size
        tcp_check = 0
        tcp_urg_ptr = 0
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = flags
        tcp_header = struct.pack("!HHLLBBHHH", tcp_source, tcp_dest, tcp_seq,
                                tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

        # pseudo header fields
        source_address = socket.inet_aton(self.local_host)
        dest_address = socket.inet_aton(self.remote_host)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        if len(payload) % 2 != 0:
            payload += b' '
        tcp_length = len(tcp_header) + len(payload)

        psh = struct.pack("!4s4sBBH", source_address, dest_address, placeholder,
                        protocol, tcp_length)
        psh = psh + tcp_header + payload
        tcp_check = self.checksum(psh)
        tcp_header = struct.pack("!HHLLBBH", tcp_source, tcp_dest,
                                tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + \
            struct.pack('!H', tcp_check) + struct.pack('!H', tcp_urg_ptr)

        return tcp_header + payload


    def _send(self, data=b'', flags=ACK):
        self.send_buf = data
        tcp_segment = self.pack_tcp_segment(data, flags=flags)
        ip_datagram = self.pack_ip_datagram(tcp_segment)
        self.rsocket.sendto(ip_datagram, (self.remote_host, self.remote_port))

    def send(self, data):
        self._send(data, flags=PSH_ACK)

        while not self.recv_ack():
            self._send(data, flags=PSH_ACK)

        # reset send_buf
        self.send_buf = ''

    def _recv(self, size=65535, delay=60):
        self.rsocket.settimeout(delay)
        try:
            while True:
                data, _ = self.rsocket.recvfrom(size)
                ip_datagram = self.unpack_ip_datagram(data)
                #print(ip_datagram)
                if ip_datagram.ip_daddr != self.local_host or ip_datagram.ip_check != 0 or ip_datagram.ip_saddr != self.remote_host:
                    continue

                tcp_seg = self.unpack_tcp_segment(ip_datagram.data)
                if tcp_seg.tcp_source != self.remote_port or tcp_seg.tcp_dest != self.local_port or tcp_seg.tcp_check != 0:
                    continue
                return tcp_seg
        except socket.timeout:
            return None

    def recv(self):
        received_segments = {}

        while True:
            tcp_seg = self._recv()
            if not tcp_seg:
                print("server down")
                self.initiates_close_connection()
                sys.exit(1)

            if tcp_seg.tcp_flags & ACK and tcp_seg.tcp_seq not in received_segments:
                received_segments[tcp_seg.tcp_seq] = tcp_seg.data
                self.tcp_ack_seq = tcp_seg.tcp_seq + len(tcp_seg.data)
                # Server wants to close connection
                if tcp_seg.tcp_flags & FIN:
                    self.reply_close_connection()
                    # Transmission is done. Server closes the connection.
                    break
                else:
                    self._send(flags=ACK)

        sorted_segments = sorted(received_segments.items())
        data = reduce(lambda x, y: x + y[-1], sorted_segments, '')

        return data

    def connect(self, host, port):
        # Three-way handshake
        self.remote_host = host
        self.remote_port = port
        self.tcp_seq = randint(0, (2 << 31) - 1)

        self._send(flags=SYN)
        if not self.recv_ack(offset=1):
            print("connect failed")
            self.initiates_close_connection()
            sys.exit(1)
        print("SYN Ok")
        self._send(flags=ACK)
        print("ACK Ok")

    def initiates_close_connection(self):
        self._send(flags=FIN_ACK)
        self.recv_ack(offset=1)

        tcp_seg = self._recv()

        if not (tcp_seg.tcp_flags & FIN):
            print("Close connection failed")
            self.initiates_close_connection()
            sys.exit(1)
        self._send(flags=ACK)
        # self.ssocket.close()
        self.rsocket.close()

    def reply_close_connection(self):
        self.tcp_ack_seq += 1
        self._send(flags=FIN_ACK)
        tcp_seg = self.recv_ack(offset=1)
        # self.ssocket.close()
        self.rsocket.close()

    def unpack_ip_datagram(self, datagram):
        '''
        Parse IP datagram
        '''
        hdr_fields = struct.unpack(IP_HDR_FMT, datagram[:20])
        ip_header_size = struct.calcsize(IP_HDR_FMT)
        ip_ver_ihl = hdr_fields[0]
        ip_ihl = ip_ver_ihl - (4 << 4)

        if ip_ihl > 5:
            opts_size = (self.ip_ihl - 5) * 4
            ip_header_size += opts_size

        ip_headers = datagram[:ip_header_size]

        data = datagram[ip_header_size:hdr_fields[2]]
        ip_check = self.checksum(ip_headers)

        return IPDatagram(ip_daddr=socket.inet_ntoa(hdr_fields[-1]),
            ip_saddr=socket.inet_ntoa(hdr_fields[-2]),
            ip_frag_off=hdr_fields[4],
            ip_id=hdr_fields[3], 
            ip_tlen=hdr_fields[2], 
            ip_check=ip_check, data=data)

    def unpack_tcp_segment(self, segment):
        '''
        Parse TCP segment
        '''
        tcp_header_size = struct.calcsize(TCP_HDR_FMT)
        hdr_fields = struct.unpack(TCP_HDR_FMT, segment[:tcp_header_size])
        tcp_source = hdr_fields[0]
        tcp_dest = hdr_fields[1]
        tcp_seq = hdr_fields[2]
        tcp_ack_seq = hdr_fields[3]
        tcp_doff_resvd = hdr_fields[4]
        tcp_doff = tcp_doff_resvd >> 4  # get the data offset
        tcp_adwind = hdr_fields[6]
        tcp_urg_ptr = hdr_fields[7]
        # parse TCP flags
        tcp_flags = hdr_fields[5]
        # process the TCP options if there are
        # currently just skip it
        if tcp_doff > 5:
            opts_size = (tcp_doff - 5) * 4
            tcp_header_size += opts_size
        # get the TCP data
        data = segment[tcp_header_size:]
        # compute the checksum of the recv packet with psh
        tcp_check = self._tcp_check(segment)
        # tcp_check = 0
        return TCPSeg(tcp_seq=tcp_seq, 
            tcp_source=tcp_source, 
            tcp_dest=tcp_dest, 
            tcp_ack_seq=tcp_ack_seq,
            tcp_adwind=tcp_adwind,
            tcp_flags=tcp_flags, tcp_check=tcp_check, data=segment[tcp_header_size:])

    def _tcp_check(self, payload):
        # pseudo header fields
        source_address = socket.inet_aton(self.local_host)
        dest_address = socket.inet_aton(self.remote_host)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(payload)

        psh = struct.pack(PSH_FMT, source_address, dest_address,
                          placeholder, protocol, tcp_length)
        psh = psh + payload

        return self.checksum(psh)

    def recv_ack(self, offset=0):
        start_time = time.time()
        while time.time() - start_time < 60:
            tcp_seg = self._recv(delay=60)
            if not tcp_seg:
                break
            if tcp_seg.tcp_flags & ACK and tcp_seg.tcp_ack_seq >= self.tcp_seq + len(self.send_buf) + offset:
                self.tcp_seq = tcp_seg.tcp_ack_seq
                self.tcp_ack_seq = tcp_seg.tcp_seq + offset
                return True

        return False


def run(url):

    host = socket.gethostbyname(url)
    s = MyTCPSocket()
    s.connect(host=host, port=77)
    s.send(b"Hello Server")

    data = s.recv()
    print(data)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('Illegal arguments')
    url = sys.argv[-1]

    run(url)

import socket
import random
import heapq
import logging
import signal
import threading
import uuid

MAX_PACKET_SIZE = 1514
MAX_HEADER_SIZE = 8
MAX_DATA_SIZE = MAX_PACKET_SIZE - MAX_HEADER_SIZE
MAX_CONFIRMATION_RETRIES = 32

LOGGER = logging.getLogger(__name__)

class Header:
    def __init__(self, syn, ack):
        self.syn = syn
        self.ack = ack
        
    def __bytes__(self, ):
        return self.syn.to_bytes(4, 'big') + self.ack.to_bytes(4, 'big')
    
    @classmethod
    def from_bytes(cls, bytes):
        return cls(int.from_bytes(bytes[:4], 'big'), 
                    int.from_bytes(bytes[4:], 'big'))
        

class TCPPacket:
    def __init__(self, data, syn=None, ack=None, header=None):
        if header:
            self.header = header
        else:
            self.header = Header(syn, ack)

        self.data = data
        
    def __bytes__(self, ):
        return bytes(self.header) + self.data
    
    @classmethod
    def from_bytes(cls, bytes):
        header = Header.from_bytes(bytes[:8])
        data = bytes[8:]
        new_obj = cls(data, header=header)
        return new_obj

    def __lt__(self, other):
        return self.header.syn < other.header.syn
        

class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data):
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg

    def close(self):
        self.udp_socket.close()


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.udp_socket.settimeout(0.001)
        self.sent_data_len = 1
        self.recv_data_len = 1
        self.uuid = uuid.uuid4()
        self.buffer = []
        self.bufferized_data = b''

    def send(self, data: bytes):
        init_data_len = self.sent_data_len
        all_data_len = len(data)
        confirmation_retries = 0

        
        data_offset = self.sent_data_len - init_data_len

        for i in range(all_data_len // MAX_DATA_SIZE + 1):
            packet = TCPPacket(data[data_offset + i * MAX_DATA_SIZE: data_offset + (i + 1) * MAX_DATA_SIZE], 
                                syn=self.sent_data_len + i * MAX_DATA_SIZE, ack=self.recv_data_len)
            self.sendto(bytes(packet))

        packets_send = all_data_len // MAX_DATA_SIZE
        while self.sent_data_len < init_data_len + all_data_len:
            try:
                recvd_bytes = self.recvfrom(MAX_PACKET_SIZE)

                recvd_packet = TCPPacket.from_bytes(recvd_bytes)

                recvd_header = recvd_packet.header
                confirmation_retries = 0
                
                if recvd_header.syn > 0:
                    if recvd_packet.header.syn == self.recv_data_len:
                        self.bufferized_data += recvd_packet.data
                        self.recv_data_len += len(recvd_packet.data)
                        self.bufferized_data += self.process_buffer()
                    else:
                        heapq.heappush(self.buffer, recvd_packet)

                    self.send_ack()
                    continue

                if recvd_header.ack <= self.sent_data_len:
                    continue

                self.sent_data_len = recvd_header.ack
            except Exception as e:
                confirmation_retries += 1
                if confirmation_retries > MAX_CONFIRMATION_RETRIES:

                    break

            if self.sent_data_len < init_data_len + all_data_len and self.sent_data_len >= init_data_len:
                offset = self.sent_data_len - init_data_len
                packet = TCPPacket(data[offset:offset + MAX_DATA_SIZE], 
                                syn=self.sent_data_len, ack=self.recv_data_len)
                self.sendto(bytes(packet))

        self.sent_data_len = init_data_len + all_data_len
        return all_data_len

    def process_buffer(self, ):
        final_data = b''
        while len(self.buffer) > 0 and self.buffer[0].header.syn <= self.recv_data_len:
            popped_packet = heapq.heappop(self.buffer)
            if popped_packet.header.syn < self.recv_data_len:
                continue
            final_data += popped_packet.data
            self.recv_data_len += len(popped_packet.data)
        
        return final_data

    def send_ack(self, ):
        conf_packet = Header(syn=0, ack=self.recv_data_len)
        self.sendto(bytes(conf_packet))

    def recv(self, n: int):
        init_recv_size = self.recv_data_len

        final_data = self.bufferized_data[:n]
        self.bufferized_data = self.bufferized_data[n:]
        n -= len(final_data)

        while self.recv_data_len < init_recv_size + n:
            try:
                final_data += self.process_buffer()

                recvd_bytes = self.recvfrom(MAX_PACKET_SIZE)
                recvd_packet = TCPPacket.from_bytes(recvd_bytes)
                
                if recvd_packet.header.syn < self.recv_data_len:

                    continue

                if recvd_packet.header.syn == self.recv_data_len:
                    final_data += recvd_packet.data
                    self.recv_data_len += len(recvd_packet.data)

                    final_data += self.process_buffer()

                else:
                    if recvd_packet.header.syn > self.recv_data_len:
                        heapq.heappush(self.buffer, recvd_packet)
            except Exception as e:
                self.send_ack()

        self.send_ack()

        return final_data

    def close(self):
        super().close()


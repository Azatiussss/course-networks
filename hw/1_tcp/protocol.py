import socket
import random
import heapq
import logging
import signal
import threading

MAX_PACKET_SIZE = 65536
MAX_HEADER_SIZE = 8
MAX_DATA_SIZE = MAX_PACKET_SIZE - MAX_HEADER_SIZE
MAX_CONFIRMATION_RETRIES = 32


LOGGER = logging.getLogger(__name__)


class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    LOGGER.info('timeout occured')
    raise TimeoutException

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
        #LOGGER.info('Decoding 1')
        header = Header.from_bytes(bytes[:8])
        #LOGGER.info('Decoding 2')
        data = bytes[8:]
        new_obj = cls(data, header=header)
        #LOGGER.info('Decoding 3')
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
        self.sent_data_len = 0
        self.recv_data_len = 0

    def send(self, data: bytes):
        init_data_len = self.sent_data_len
        all_data_len = len(data)
        confirmation_retries = 0

        #LOGGER.info(f"Ready to send {init_data_len}")
        
        data_offset = self.sent_data_len - init_data_len
        for i in range(all_data_len // MAX_DATA_SIZE + 1):
            packet = TCPPacket(data[data_offset + i * MAX_DATA_SIZE: data_offset + (i + 1) * MAX_DATA_SIZE], 
                                syn=self.sent_data_len, ack=self.recv_data_len)
            self.sendto(bytes(packet))

        packets_send = all_data_len // MAX_DATA_SIZE
        while self.sent_data_len < init_data_len + all_data_len:
           # LOGGER.info(f'Waiting for confirm')
            try:
                #LOGGER.info(f'Waiting for confirm')
                recvd_bytes = self.recvfrom(MAX_HEADER_SIZE)
                #LOGGER.info(f'Confirmed')
                recvd_header = Header.from_bytes(recvd_bytes)
                
                if recvd_header.syn <= self.recv_data_len:
                    continue

                confirmation_retries = 0
                self.sent_data_len = recvd_header.ack
                #LOGGER.info(f'Confirmed receiving {self.sent_data_len}')
                self.recv_data_len = recvd_header.syn #+ 1
            except Exception as e:
                #LOGGER.info(f'Confirmation timed out')
                confirmation_retries += 1
                if confirmation_retries > MAX_CONFIRMATION_RETRIES:
                    self.recv_data_len += 1
                    break

            if self.sent_data_len < init_data_len + all_data_len:
                packet = TCPPacket(data[self.sent_data_len - init_data_len:self.sent_data_len - init_data_len + MAX_DATA_SIZE], 
                                    syn=self.sent_data_len, ack=self.recv_data_len)
                self.sendto(bytes(packet))
                
       # LOGGER.info("-------------------------------------------------------------")

        return all_data_len

    def recv(self, n: int):
        init_recv_size = self.recv_data_len

        buffer = []
        final_data = b''
        
        #LOGGER.info(f'Ready to recv, {self.recv_data_len}')
        while self.recv_data_len < init_recv_size + n:
            #LOGGER.info(f'Ready to recv')
            try:
                #LOGGER.info(f'Waiting for packet')
                recvd_bytes = self.recvfrom(MAX_PACKET_SIZE)
                #LOGGER.info(f'Recieved packet {len(recvd_bytes)}')
                recvd_packet = TCPPacket.from_bytes(recvd_bytes)
                
                #recv_segment = recvd_packet.header.syn
                #LOGGER.info(f'{recvd_packet.header.syn} - {self.recv_size}')
                #LOGGER.info(f'Recieved conf {self.recvd_conf}')
                if recvd_packet.header.syn < self.recv_data_len:
                    continue

                if recvd_packet.header.syn == self.recv_data_len:
                    final_data += recvd_packet.data
                    self.recv_data_len += len(recvd_packet.data)

                    #LOGGER.info(f'Update recv_size {recv_size}')

                    while len(buffer) > 0 and buffer[0].syn == self.recv_data_len:
                        popped_packet = heapq.heappop(buffer)
                        final_data += popped_packet.data
                        self.recv_data_len += len(popped_packet.data)

                    #LOGGER.info(f'Sending confirmation')
                else:
                    if recvd_packet.header.syn > self.recv_data_len:
                        heapq.heappush(buffer, recvd_packet)
            except Exception as e:
                conf_packet = Header(syn=self.sent_data_len, ack=self.recv_data_len)
                self.sendto(bytes(conf_packet))

        conf_packet = Header(syn=self.sent_data_len, ack=self.recv_data_len)
        self.sendto(bytes(conf_packet))
        self.sent_data_len += 1
        #LOGGER.info(final_data)
        return final_data
    
    def close(self):
        super().close()

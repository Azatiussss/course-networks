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
        self.udp_socket.settimeout(0.01)
        self.sent_data_len = 1
        self.recv_data_len = 1
        self.uuid = uuid.uuid4()
        self.buffer = []

    def send(self, data: bytes):
        init_data_len = self.sent_data_len
        all_data_len = len(data)
        confirmation_retries = 0

        #LOGGER.info(f"Ready to send {init_data_len}")
        
        data_offset = self.sent_data_len - init_data_len
        i = 0
       # for i in range(all_data_len // MAX_DATA_SIZE + 1):
        packet = TCPPacket(data[data_offset + i * MAX_DATA_SIZE: data_offset + (i + 1) * MAX_DATA_SIZE], 
                                syn=self.sent_data_len + i * MAX_DATA_SIZE, ack=self.recv_data_len)
        self.sendto(bytes(packet))
            #LOGGER.info(f"{self.uuid} Ready to send {len(data[data_offset + i * MAX_DATA_SIZE: data_offset + (i + 1) * MAX_DATA_SIZE])}")

        packets_send = all_data_len // MAX_DATA_SIZE
        while self.sent_data_len < init_data_len + all_data_len:
            #LOGGER.info(f'Waiting for confirm')
            try:
                #LOGGER.info(f'Waiting for confirm')
                recvd_bytes = self.recvfrom(MAX_HEADER_SIZE)
                #LOGGER.info(f'Confirmed')
                recvd_header = Header.from_bytes(recvd_bytes)
                confirmation_retries = 0
                
                #if recvd_header.syn <= self.recv_data_len:
                 #   
                #if self.sent_data_len < recvd_header.ack:
                 #   confirmation_retries = 0
                if recvd_header.ack <= self.sent_data_len:
                    continue

                self.sent_data_len = recvd_header.ack #max(recvd_header.ack, self.sent_data_len)
                #LOGGER.info(f'{self.uuid} Confirmed receiving {self.sent_data_len} {recvd_header.ack} {init_data_len + all_data_len} {confirmation_retries}')
                #self.recv_data_len = recvd_header.syn #+ 1
            except Exception as e:
                #LOGGER.info(f'Confirmation timed out')
                confirmation_retries += 1
                if confirmation_retries > MAX_CONFIRMATION_RETRIES:
                   # self.recv_data_len += 1
                    break

            if self.sent_data_len < init_data_len + all_data_len and self.sent_data_len >= init_data_len:
                offset = self.sent_data_len - init_data_len
                #LOGGER.info(f"{self.uuid} {(all_data_len + init_data_len - self.sent_data_len) // MAX_DATA_SIZE}")
                for i in range((all_data_len + init_data_len - self.sent_data_len) // MAX_DATA_SIZE + 1):
                    packet = TCPPacket(data[offset + i * MAX_DATA_SIZE:offset + (i + 1) * MAX_DATA_SIZE], 
                                    syn=self.sent_data_len + i * MAX_DATA_SIZE, ack=self.recv_data_len)
                    self.sendto(bytes(packet))
                    #LOGGER.info(f"{self.uuid} Resent frame {self.sent_data_len + i * MAX_DATA_SIZE}")
        #LOGGER.info("-------------------------------------------------------------")
        self.sent_data_len = init_data_len + all_data_len
        return all_data_len

    def recv(self, n: int):
        init_recv_size = self.recv_data_len

        #buffer = []
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
                #LOGGER.info(f'{self.uuid} {recvd_packet.header.syn} - {self.recv_data_len} - {len(recvd_packet.data)}')
                #LOGGER.info(f'Recieved conf {self.recvd_conf}')
                if recvd_packet.header.syn < self.recv_data_len:
                #    conf_packet = Header(syn=0, ack=self.recv_data_len)
                 #   self.sendto(bytes(conf_packet))
                    continue

                if recvd_packet.header.syn == self.recv_data_len:
                    final_data += recvd_packet.data
                    self.recv_data_len += len(recvd_packet.data)

                    #LOGGER.info(f'Update recv_size {recv_size}')

                    while len(self.buffer) > 0 and self.buffer[0].header.syn <= self.recv_data_len:
                        popped_packet = heapq.heappop(self.buffer)
                        if popped_packet.header.syn < self.recv_data_len:
                            continue
                        final_data += popped_packet.data
                        self.recv_data_len += len(popped_packet.data)
                        #LOGGER.info(f'{self.uuid} extracting saved chunks')

                    #LOGGER.info(f'Sending confirmation')
                else:
                    if recvd_packet.header.syn > self.recv_data_len:
                        heapq.heappush(self.buffer, recvd_packet)
            except Exception as e:
                #LOGGER.info(f'{self.uuid} {e}')
                conf_packet = Header(syn=0, ack=self.recv_data_len)
                self.sendto(bytes(conf_packet))

        conf_packet = Header(syn=0, ack=self.recv_data_len)
        self.sendto(bytes(conf_packet))
       # self.sent_data_len += 1
        #LOGGER.info(final_data)
        return final_data

    def close(self):
        super().close()


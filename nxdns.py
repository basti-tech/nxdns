#!/usr/bin/python3
import argparse
import sys
import threading
import socketserver
import struct
import datetime
import traceback
import logging
from logging.handlers import RotatingFileHandler
from dnslib import *

def dns_response(data):
    request = DNSRecord.parse(data)
    reply = request.reply()
    reply.header.rcode = RCODE.NXDOMAIN
    return reply.pack()

class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        logger = logging.getLogger('fake_dns')
        try:
            data = self.get_data()
            try:
                request = DNSRecord.parse(data)
                qname = str(request.q.qname)
            except Exception:
                qname = "<unparsable>"
            
            logger.info("%s request from %s:%s for %s", self.__class__.__name__[:3], self.client_address[0], self.client_address[1], qname)
            
            self.send_data(dns_response(data))
        except Exception as e:
            logger.error("Error handling request from %s:%s - %s", self.client_address[0], self.client_address[1], str(e))
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192)
        if len(data) < 2:
            raise Exception("TCP packet too small")
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)

class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

def main():
    parser = argparse.ArgumentParser(description='Start a Fake DNS implemented in Python. Only returns NXDOMAIN and logs requests into a file. Usually DNSes use UDP on port 53.')
    parser.add_argument('--port', default=53, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    logger = logging.getLogger('fake_dns')
    logger.setLevel(logging.INFO)
    fh = RotatingFileHandler('dns_log.txt', maxBytes=5*1024*1024, backupCount=5)
    fh.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(ch)

    logger.info("Starting nameserver...")

    servers = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer(('', args.port), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        logger = logging.getLogger('fake_dns')
        logger.info("%s server loop running in thread: %s", s.RequestHandlerClass.__name__[:3], thread.name)

    try:
        while 1:
            time.sleep(1)

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()
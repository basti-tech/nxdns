#!/usr/bin/python3
import argparse
import sys
import threading
import socketserver
import struct
import datetime
import traceback
import logging
import ssl
import configparser
import os
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
        logger = logging.getLogger('nxdns')
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
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file.')
    parser.add_argument('--port', type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    parser.add_argument('--tls', action='store_true', help='Listen to DNS over TLS (DoT).')
    parser.add_argument('--tls-port', type=int, help='The port for DoT (default: 853).')
    parser.add_argument('--cert', type=str, help='Path to the TLS certificate file (required for DoT).')
    parser.add_argument('--key', type=str, help='Path to the TLS private key file (required for DoT).')
    parser.add_argument('--max-log-size', type=int, help='Maximum log file size in MB.')
    parser.add_argument('--log-file', type=str, help='Path to the log file (default: dns_log.txt).')
    args = parser.parse_args()

    config = {
        'port': 53,
        'tcp': False,
        'udp': False,
        'tls': False,
        'tls_port': 853,
        'cert': None,
        'key': None,
        'max_log_size': 5,
        'log_file': 'nxdns_log.txt'
    }

    config_file = args.config if args.config else 'nxdns.conf'
    if os.path.exists(config_file):
        cp = configparser.ConfigParser()
        cp.read(config_file)
        if 'nxdns' in cp:
            sec = cp['nxdns']
            if 'port' in sec: config['port'] = sec.getint('port')
            if 'tcp' in sec: config['tcp'] = sec.getboolean('tcp')
            if 'udp' in sec: config['udp'] = sec.getboolean('udp')
            if 'tls' in sec: config['tls'] = sec.getboolean('tls')
            if 'tls_port' in sec: config['tls_port'] = sec.getint('tls_port')
            if 'cert' in sec: config['cert'] = sec.get('cert')
            if 'key' in sec: config['key'] = sec.get('key')
            if 'max_log_size' in sec: config['max_log_size'] = sec.getint('max_log_size')
            if 'log_file' in sec: config['log_file'] = sec.get('log_file')

    # CLI overrides
    if args.port is not None: config['port'] = args.port
    if args.tcp: config['tcp'] = True
    if args.udp: config['udp'] = True
    if args.tls: config['tls'] = True
    if args.tls_port is not None: config['tls_port'] = args.tls_port
    if args.cert is not None: config['cert'] = args.cert
    if args.key is not None: config['key'] = args.key
    if args.max_log_size is not None: config['max_log_size'] = args.max_log_size
    if args.log_file is not None: config['log_file'] = args.log_file

    if not (config['udp'] or config['tcp'] or config['tls']): 
        parser.error("Please select at least one of --udp, --tcp, or --tls (via CLI or config file).")
    if config['tls'] and (not config['cert'] or not config['key']): 
        parser.error("--tls requires --cert and --key to be provided.")

    logger = logging.getLogger('nxdns')
    logger.setLevel(logging.INFO)
    fh = RotatingFileHandler(config['log_file'], maxBytes=config['max_log_size']*1024*1024, backupCount=5)
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
    if config['udp']: servers.append(socketserver.ThreadingUDPServer(('', config['port']), UDPRequestHandler))
    if config['tcp']: servers.append(socketserver.ThreadingTCPServer(('', config['port']), TCPRequestHandler))
    
    if config['tls']:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=config['cert'], keyfile=config['key'])
        tls_server = socketserver.ThreadingTCPServer(('', config['tls_port']), TCPRequestHandler)
        tls_server.socket = context.wrap_socket(tls_server.socket, server_side=True)
        servers.append(tls_server)

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        logger = logging.getLogger('nxdns')
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
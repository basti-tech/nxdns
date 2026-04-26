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
import http.server
import urllib.parse
import base64
from logging.handlers import RotatingFileHandler
from dnslib import *

def dns_response(data):
    request = DNSRecord.parse(data)
    reply = request.reply()
    reply.header.rcode = RCODE.NXDOMAIN
    return reply.pack()

def process_dns_query(data, protocol_name, client_ip, client_port):
    logger = logging.getLogger('nxdns')
    try:
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)
    except Exception:
        qname = "<unparsable>"
    
    logger.info("%s request from %s:%s for %s", protocol_name, client_ip, client_port, qname)
    return dns_response(data)

class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        try:
            data = self.get_data()
            response = process_dns_query(data, self.__class__.__name__[:3], self.client_address[0], self.client_address[1])
            self.send_data(response)
        except Exception as e:
            logger = logging.getLogger('nxdns')
            logger.error("Error handling request from %s:%s - %s", self.client_address[0], self.client_address[1], str(e))
            traceback.print_exc(file=sys.stderr)

class DoHRequestHandler(http.server.BaseHTTPRequestHandler):
    def send_dns_response(self, data):
        try:
            response = process_dns_query(data, "DoH", self.client_address[0], self.client_address[1])
            self.send_response(200)
            self.send_header('Content-Type', 'application/dns-message')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            self.wfile.write(response)
        except Exception as e:
            self.send_error(400, "Bad Request")

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        if parsed_path.path != '/dns-query':
            self.send_error(404, "Not Found")
            return
        qs = urllib.parse.parse_qs(parsed_path.query)
        dns_param = qs.get('dns', [None])[0]
        if not dns_param:
            self.send_error(400, "Missing dns parameter")
            return
        try:
            padding = '=' * (4 - (len(dns_param) % 4))
            data = base64.urlsafe_b64decode(dns_param + padding)
            self.send_dns_response(data)
        except Exception:
            self.send_error(400, "Invalid base64 payload")

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        if parsed_path.path != '/dns-query':
            self.send_error(404, "Not Found")
            return
        if self.headers.get('Content-Type') != 'application/dns-message':
            self.send_error(415, "Unsupported Media Type")
            return
        content_length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(content_length)
        self.send_dns_response(data)
    
    def log_message(self, format, *args):
        pass


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
    parser.add_argument('--doh', action='store_true', help='Listen to DNS over HTTPS (DoH).')
    parser.add_argument('--doh-port', type=int, help='The port for DoH (default: 443).')
    parser.add_argument('--cert', type=str, help='Path to the TLS certificate file (required for DoT/DoH).')
    parser.add_argument('--key', type=str, help='Path to the TLS private key file (required for DoT/DoH).')
    parser.add_argument('--max-log-size', type=int, help='Maximum log file size in MB.')
    parser.add_argument('--log-file', type=str, help='Path to the log file (default: dns_log.txt).')
    args = parser.parse_args()

    config = {
        'port': 53,
        'tcp': False,
        'udp': False,
        'tls': False,
        'tls_port': 853,
        'doh': False,
        'doh_port': 443,
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
            if 'doh' in sec: config['doh'] = sec.getboolean('doh')
            if 'doh_port' in sec: config['doh_port'] = sec.getint('doh_port')
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
    if args.doh: config['doh'] = True
    if args.doh_port is not None: config['doh_port'] = args.doh_port
    if args.cert is not None: config['cert'] = args.cert
    if args.key is not None: config['key'] = args.key
    if args.max_log_size is not None: config['max_log_size'] = args.max_log_size
    if args.log_file is not None: config['log_file'] = args.log_file

    if not (config['udp'] or config['tcp'] or config['tls'] or config['doh']): 
        parser.error("Please select at least one of --udp, --tcp, --tls, or --doh (via CLI or config file).")
    if (config['tls'] or config['doh']) and (not config['cert'] or not config['key']): 
        parser.error("--tls and --doh require --cert and --key to be provided.")

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
    
    if config['tls'] or config['doh']:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=config['cert'], keyfile=config['key'])
        
        if config['tls']:
            tls_server = socketserver.ThreadingTCPServer(('', config['tls_port']), TCPRequestHandler)
            tls_server.socket = context.wrap_socket(tls_server.socket, server_side=True)
            servers.append(tls_server)
        
        if config['doh']:
            doh_server = socketserver.ThreadingTCPServer(('', config['doh_port']), DoHRequestHandler)
            doh_server.socket = context.wrap_socket(doh_server.socket, server_side=True)
            servers.append(doh_server)

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
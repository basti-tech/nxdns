#!/usr/bin/env python3
import argparse
import sys
import time
import threading
import concurrent.futures
import socketserver
import struct
import datetime
import logging

logger = logging.getLogger('nxdns')
import ssl
import configparser
import os
import socket
import http.server
import urllib.parse
import base64
from logging.handlers import RotatingFileHandler
from dnslib import *
import asyncio
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

def process_dns_query(data, protocol_name, client_ip, client_port):
    try:
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)
        logger.info("%s request from %s:%s for %s", protocol_name, client_ip, client_port, qname)
        
        reply = request.reply()
        reply.header.rcode = RCODE.NXDOMAIN
        return reply.pack()
    except Exception as e:
        logger.warning("%s unparsable/invalid request from %s:%s - %s", protocol_name, client_ip, client_port, str(e))
        raise ValueError("Invalid DNS packet")

class ThreadPoolMixIn:
    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

    def process_request(self, request, client_address):
        self.executor.submit(self.process_request_thread, request, client_address)

class PoolUDPServer(ThreadPoolMixIn, socketserver.UDPServer):
    def __init__(self, server_address, RequestHandlerClass, max_workers=100, bind_and_activate=True):
        host = server_address[0]
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()
    def server_close(self):
        super().server_close()
        self.executor.shutdown(wait=False)

class PoolTCPServer(ThreadPoolMixIn, socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, max_workers=100, bind_and_activate=True):
        host = server_address[0]
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()
    def server_close(self):
        super().server_close()
        self.executor.shutdown(wait=False)

# Aliases kept for clarity at call sites
DualStackPoolUDPServer = PoolUDPServer
DualStackPoolTCPServer = PoolTCPServer


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
            logger.exception("Error handling request from %s:%s", self.client_address[0], self.client_address[1])

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
    MAX_DNS_PACKET = 4096  # DNS messages over TCP are never legitimately larger

    def setup(self):
        super().setup()
        self.request.settimeout(5)  # prevent slow-read attacks

    def get_data(self):
        raw_len = self._recv_exact(2)
        sz = struct.unpack('>H', raw_len)[0]
        if sz == 0:
            raise Exception("TCP packet has zero length")
        if sz > self.MAX_DNS_PACKET:
            raise Exception(f"TCP packet too large: {sz} bytes (max {self.MAX_DNS_PACKET})")
        return self._recv_exact(sz)

    def _recv_exact(self, n):
        buf = b''
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                raise Exception("Connection closed before complete packet received")
            buf += chunk
        return buf

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

class DoQProtocol(QuicConnectionProtocol):
    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            try:
                peername = self._transport.get_extra_info('peername')
                client_ip = peername[0] if peername else "Unknown"
                client_port = peername[1] if peername else 0

                # RFC 9250: DoQ DNS messages are prefixed with a 2-byte length (same as TCP)
                data = event.data
                if len(data) < 2:
                    raise ValueError("DoQ stream data too short")
                sz = struct.unpack('>H', data[:2])[0]
                dns_data = data[2:2 + sz]

                response = process_dns_query(dns_data, "DoQ", client_ip, client_port)

                # Prepend 2-byte length prefix on the response
                prefixed = struct.pack('>H', len(response)) + response
                self._quic.send_stream_data(event.stream_id, prefixed, end_stream=True)
                self.transmit()
            except Exception as e:
                logger.error("DoQ error: %s", e)


def start_doq_server(host, port, cert, key):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    configuration = QuicConfiguration(is_client=False, alpn_protocols=["doq"])
    configuration.load_cert_chain(cert, key)
    loop.run_until_complete(serve(host, port, configuration=configuration, create_protocol=DoQProtocol))
    logger.info("DoQ server loop running in background asyncio loop")
    loop.run_forever()

def main():
    parser = argparse.ArgumentParser(description='Start a Fake DNS implemented in Python. Only returns NXDOMAIN and logs requests into a file. Usually DNSes use UDP on port 53.')
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file.')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='The interface to listen on (default: 127.0.0.1). Use :: or "" for all interfaces with DualStack support.')
    parser.add_argument('--port', type=int, default=53, help='The port to listen on (default: 53).')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    parser.add_argument('--tls', action='store_true', help='Listen to DNS over TLS (DoT).')
    parser.add_argument('--tls-port', type=int, default=853, help='The port for DoT (default: 853).')
    parser.add_argument('--doh', action='store_true', help='Listen to DNS over HTTPS (DoH).')
    parser.add_argument('--doh-port', type=int, default=443, help='The port for DoH (default: 443).')
    parser.add_argument('--cert', type=str, help='Path to the TLS certificate file (required for DoT/DoH/DoQ).')
    parser.add_argument('--key', type=str, help='Path to the TLS private key file (required for DoT/DoH/DoQ).')
    parser.add_argument('--max-log-size', type=int, default=5, help='Maximum log file size in MB.')
    parser.add_argument('--log-file', type=str, default='nxdns_log.txt', help='Path to the log file (default: nxdns_log.txt).')
    parser.add_argument('--doq', action='store_true', help='Listen to DNS over QUIC (DoQ). Requires aioquic.')
    parser.add_argument('--doq-port', type=int, default=853, help='The port for DoQ (default: 853).')
    parser.add_argument('--workers', type=int, default=100, help='Maximum number of threads for processing requests (default: 100).')
    args = parser.parse_args()

    config = vars(args).copy()
    config_file = args.config if args.config else 'nxdns.conf'
    
    cli_args_provided = False
    for arg in sys.argv[1:]:
        if arg not in ('-c', '--config') and not arg.startswith('--config=') and arg != args.config:
            cli_args_provided = True
            break

    if not cli_args_provided and os.path.exists(config_file):
        cp = configparser.ConfigParser()
        cp.read(config_file)
        if 'nxdns' in cp:
            sec = cp['nxdns']
            for k in ['tcp', 'udp', 'tls', 'doh', 'doq']:
                if k in sec: config[k] = sec.getboolean(k)
            for k in ['port', 'tls_port', 'doh_port', 'doq_port', 'max_log_size', 'workers']:
                if k in sec: config[k] = sec.getint(k)
            for k in ['cert', 'key', 'log_file', 'host']:
                if k in sec: config[k] = sec.get(k)

    if not (config['udp'] or config['tcp'] or config['tls'] or config['doh'] or config['doq']): 
        parser.error("Please select at least one of --udp, --tcp, --tls, --doh, or --doq (via CLI or config file).")
    if (config['tls'] or config['doh'] or config['doq']) and (not config['cert'] or not config['key']): 
        parser.error("--tls, --doh, and --doq require --cert and --key to be provided.")


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
    if config['udp']: servers.append(DualStackPoolUDPServer((config['host'], config['port']), UDPRequestHandler, max_workers=config['workers']))
    if config['tcp']: servers.append(DualStackPoolTCPServer((config['host'], config['port']), TCPRequestHandler, max_workers=config['workers']))
    
    if config['tls'] or config['doh']:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=config['cert'], keyfile=config['key'])
        
        if config['tls']:
            tls_server = DualStackPoolTCPServer((config['host'], config['tls_port']), TCPRequestHandler, max_workers=config['workers'])
            tls_server.socket = context.wrap_socket(tls_server.socket, server_side=True)
            servers.append(tls_server)
        
        if config['doh']:
            doh_server = DualStackPoolTCPServer((config['host'], config['doh_port']), DoHRequestHandler, max_workers=config['workers'])
            doh_server.socket = context.wrap_socket(doh_server.socket, server_side=True)
            servers.append(doh_server)

    if config['doq']:
        doq_thread = threading.Thread(target=start_doq_server, args=(config['host'], config['doq_port'], config['cert'], config['key']))
        doq_thread.daemon = True
        doq_thread.start()

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
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
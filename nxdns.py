#!/usr/bin/env python3
import argparse
import sys
import time
import threading
import concurrent.futures
import socketserver
import struct
import logging
import signal

logger = logging.getLogger('nxdns')
import ssl
import configparser
import os
import socket
try:
    import pwd
    import grp
except ImportError:
    pwd = None
    grp = None

import http.server
import urllib.parse
import base64
from logging.handlers import RotatingFileHandler
from dnslib import *
import asyncio

stop_event = threading.Event()

def signal_handler(signum, frame):
    logger.info("Received termination signal (%s), shutting down...", signum)
    stop_event.set()

def drop_privileges(user, group=None, log_file=None):
    """Drop root privileges to the specified user/group after sockets are bound."""
    if pwd is None or grp is None:
        logger.warning("--user/--group specified but not supported on this platform, skipping privilege drop.")
        return
    if os.getuid() != 0:
        logger.warning("--user specified but not running as root, skipping privilege drop.")
        return
    try:
        pw = pwd.getpwnam(user)
        target_uid = pw.pw_uid
        target_gid = grp.getgrnam(group).gr_gid if group else pw.pw_gid

        if log_file and os.path.exists(log_file):
            try:
                os.chown(log_file, target_uid, target_gid)
            except OSError as e:
                logger.warning("Could not change ownership of log file %s: %s", log_file, e)

        os.setgroups([])           # Drop supplementary groups
        os.setgid(target_gid)      # Set GID first (can't do it after setuid)
        os.setuid(target_uid)      # Drop to unprivileged user
        logger.info("Dropped privileges to %s (uid=%d, gid=%d)", user, target_uid, target_gid)
    except KeyError as e:
        logger.error("Unknown user or group for privilege drop: %s", e)
        sys.exit(1)
    except PermissionError as e:
        logger.error("Failed to drop privileges: %s", e)
        sys.exit(1)

def process_dns_query(data, protocol_name, client_ip, client_port):
    try:
        request = DNSRecord.parse(data)
        # RFC 1035: Never reply to response packets (QR=1) to prevent reflection/amplification loops
        if request.header.qr != 0:
            logger.debug("%s ignoring DNS response packet (QR=1) from %s:%s", protocol_name, client_ip, client_port)
            return None

        if request.q:
            raw_qname = str(request.q.qname)
            # Sanitize qname to prevent log injection (CRLF / control characters)
            qname = "".join(c for c in raw_qname if c.isprintable() and c not in "\r\n")
            qtype = QTYPE.get(request.q.qtype, str(request.q.qtype))
        else:
            qname = "<empty>"
            qtype = "<none>"

        logger.info("%s request from %s:%s for %s (%s)", protocol_name, client_ip, client_port, qname, qtype)
        
        reply = request.reply()
        reply.header.aa = 1
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
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, max_workers=100, bind_and_activate=True):
        host = server_address[0]
        self.address_family = socket.AF_INET6 if (":" in host or host == "") else socket.AF_INET
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        bind_host = "::" if (host == "" and self.address_family == socket.AF_INET6) else host
        super().__init__((bind_host, server_address[1]), RequestHandlerClass, bind_and_activate)

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except (AttributeError, OSError):
                pass
        super().server_bind()

    def server_close(self):
        super().server_close()
        self.executor.shutdown(wait=False)

class PoolTCPServer(ThreadPoolMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, server_address, RequestHandlerClass, max_workers=100, bind_and_activate=True, ssl_context=None):
        host = server_address[0]
        self.address_family = socket.AF_INET6 if (":" in host or host == "") else socket.AF_INET
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        self.ssl_context = ssl_context
        bind_host = "::" if (host == "" and self.address_family == socket.AF_INET6) else host
        super().__init__((bind_host, server_address[1]), RequestHandlerClass, bind_and_activate)

    def finish_request(self, request, client_address):
        if self.ssl_context:
            request.settimeout(5.0)  # Handshake timeout
            try:
                request = self.ssl_context.wrap_socket(request, server_side=True)
            except Exception as e:
                logger.debug("TLS handshake failed for %s:%s - %s", client_address[0], client_address[1], e)
                return
        self.RequestHandlerClass(request, client_address, self)

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except (AttributeError, OSError):
                pass
        super().server_bind()

    def server_close(self):
        super().server_close()
        self.executor.shutdown(wait=False)

DualStackPoolUDPServer = PoolUDPServer
DualStackPoolTCPServer = PoolTCPServer


class BaseRequestHandler(socketserver.BaseRequestHandler):
    PROTOCOL_NAME = "DNS"

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        try:
            data = self.get_data()
            if data is None:
                return
            response = process_dns_query(data, self.PROTOCOL_NAME, self.client_address[0], self.client_address[1])
            if response is not None:
                self.send_data(response)
        except (ConnectionResetError, BrokenPipeError, TimeoutError, socket.timeout):
            pass
        except ValueError:
            pass
        except Exception as e:
            logger.exception("Error handling request from %s:%s", self.client_address[0], self.client_address[1])

class DoHRequestHandler(http.server.BaseHTTPRequestHandler):
    MAX_DOH_PAYLOAD = 65535  # Max standard DNS message size

    def setup(self):
        super().setup()
        self.request.settimeout(5.0)  # Slowloris mitigation

    def send_dns_response(self, data):
        try:
            response = process_dns_query(data, "DoH", self.client_address[0], self.client_address[1])
            if response is None:
                self.send_error(400, "Bad Request (Invalid DNS Query)")
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/dns-message')
            self.send_header('Content-Length', str(len(response)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(response)
        except Exception as e:
            self.send_error(400, "Bad Request")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Accept')
        self.send_header('Content-Length', '0')
        self.end_headers()

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
            padding = '=' * (-len(dns_param) % 4)
            data = base64.urlsafe_b64decode(dns_param + padding)
            if len(data) > self.MAX_DOH_PAYLOAD:
                self.send_error(413, "Payload Too Large")
                return
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
        try:
            content_length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return

        if content_length > self.MAX_DOH_PAYLOAD:
            self.send_error(413, "Payload Too Large")
            return
        if content_length <= 0:
            self.send_error(400, "Empty Payload")
            return

        data = self.rfile.read(content_length)
        self.send_dns_response(data)
    
    def log_message(self, format, *args):
        pass


class TCPRequestHandler(BaseRequestHandler):
    PROTOCOL_NAME = "TCP"
    MAX_DNS_PACKET = 4096  # DNS messages over TCP are never legitimately larger

    def setup(self):
        super().setup()
        self.request.settimeout(5.0)  # Idle timeout between queries

    def get_data(self):
        raw_len = self._recv_exact(2)
        if not raw_len:
            return None
        sz = struct.unpack('>H', raw_len)[0]
        if sz == 0:
            return None
        if sz > self.MAX_DNS_PACKET:
            raise ValueError(f"TCP packet too large: {sz} bytes (max {self.MAX_DNS_PACKET})")
        return self._recv_exact(sz)

    def _recv_exact(self, n):
        buf = b''
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                if not buf:
                    return None
                raise ConnectionResetError("Connection closed before complete packet received")
            buf += chunk
        return buf

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)

    def handle(self):
        # RFC 7766: Support multiple queries on a single persistent TCP connection
        while True:
            try:
                data = self.get_data()
                if data is None:
                    break
                response = process_dns_query(data, self.PROTOCOL_NAME, self.client_address[0], self.client_address[1])
                if response is not None:
                    self.send_data(response)
            except (ConnectionResetError, BrokenPipeError, TimeoutError, socket.timeout):
                break
            except ValueError:
                break
            except Exception as e:
                logger.exception("Error handling request from %s:%s", self.client_address[0], self.client_address[1])
                break


class DoTRequestHandler(TCPRequestHandler):
    PROTOCOL_NAME = "DoT"


class UDPRequestHandler(BaseRequestHandler):
    PROTOCOL_NAME = "UDP"

    def get_data(self):
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

def start_doq_server(cert, key, host, port, ready_event):
    try:
        from aioquic.asyncio import QuicConnectionProtocol, serve
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import StreamDataReceived
    except ImportError:
        logger.error("aioquic is required for DoQ support. Install it with: pip install aioquic")
        sys.exit(1)

    class DoQProtocol(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._buffers = {}

        def quic_event_received(self, event):
            if isinstance(event, StreamDataReceived):
                try:
                    stream_id = event.stream_id
                    if stream_id not in self._buffers:
                        self._buffers[stream_id] = bytearray()
                    self._buffers[stream_id].extend(event.data)
                    buf = self._buffers[stream_id]

                    # RFC 9250: Each DoQ stream carries a 2-byte length-prefixed DNS message
                    if len(buf) >= 2:
                        sz = struct.unpack('>H', buf[:2])[0]
                        if len(buf) >= 2 + sz:
                            dns_data = bytes(buf[2:2 + sz])
                            del self._buffers[stream_id]

                            paths = self._quic._network_paths
                            if paths:
                                client_ip, client_port = paths[0].addr[0], paths[0].addr[1]
                            else:
                                client_ip, client_port = "Unknown", 0

                            response = process_dns_query(dns_data, "DoQ", client_ip, client_port)
                            if response is not None:
                                prefixed = struct.pack('>H', len(response)) + response
                                self._quic.send_stream_data(stream_id, prefixed, end_stream=True)
                                self.transmit()
                except Exception as e:
                    logger.error("DoQ error: %s", e)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    configuration = QuicConfiguration(is_client=False, alpn_protocols=["doq"])
    configuration.load_cert_chain(cert, key)

    async def _serve():
        bind_host = "::" if host == "" else host
        await serve(bind_host, port, configuration=configuration, create_protocol=DoQProtocol)
        ready_event.set()  # socket is now bound, main thread can drop privileges

    loop.run_until_complete(_serve())
    logger.info("DoQ server loop running in background asyncio loop")
    loop.run_forever()

def main():
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)

    # 1. First pass: check for -c / --config
    conf_parser = argparse.ArgumentParser(add_help=False)
    conf_parser.add_argument('-c', '--config', type=str, default='nxdns.conf', help='Path to configuration file.')
    conf_args, _ = conf_parser.parse_known_args()

    defaults = {
        'host': '127.0.0.1',
        'port': 53,
        'tcp': False,
        'udp': False,
        'tls': False,
        'tls_port': 853,
        'doh': False,
        'doh_port': 443,
        'doq': False,
        'doq_port': 853,
        'cert': None,
        'key': None,
        'max_log_size': 5,
        'log_file': 'dns_log.txt',
        'workers': 100,
        'user': None,
        'group': None,
    }

    if os.path.exists(conf_args.config):
        cp = configparser.ConfigParser()
        cp.read(conf_args.config)
        if 'nxdns' in cp:
            sec = cp['nxdns']
            for k in ['tcp', 'udp', 'tls', 'doh', 'doq']:
                if k in sec:
                    defaults[k] = sec.getboolean(k)
            for k in ['port', 'tls_port', 'doh_port', 'doq_port', 'max_log_size', 'workers']:
                if k in sec:
                    defaults[k] = sec.getint(k)
            for k in ['cert', 'key', 'log_file', 'host', 'user', 'group']:
                if k in sec:
                    defaults[k] = sec.get(k)

    # 2. Main argument parser
    parser = argparse.ArgumentParser(
        parents=[conf_parser],
        description='Start a Fake DNS implemented in Python. Only returns NXDOMAIN and logs requests into a file.'
    )
    parser.add_argument('--host', type=str, default=None, help='The interface to listen on (default: 127.0.0.1). Use :: or "" for DualStack support.')
    parser.add_argument('--port', type=int, default=None, help='The port to listen on (default: 53).')
    parser.add_argument('--tcp', dest='tcp', action='store_true', default=None, help='Listen to TCP connections.')
    parser.add_argument('--no-tcp', dest='tcp', action='store_false', help='Disable TCP connections.')
    parser.add_argument('--udp', dest='udp', action='store_true', default=None, help='Listen to UDP datagrams.')
    parser.add_argument('--no-udp', dest='udp', action='store_false', help='Disable UDP datagrams.')
    parser.add_argument('--tls', dest='tls', action='store_true', default=None, help='Listen to DNS over TLS (DoT).')
    parser.add_argument('--no-tls', dest='tls', action='store_false', help='Disable DoT.')
    parser.add_argument('--tls-port', type=int, default=None, help='The port for DoT (default: 853).')
    parser.add_argument('--doh', dest='doh', action='store_true', default=None, help='Listen to DNS over HTTPS (DoH).')
    parser.add_argument('--no-doh', dest='doh', action='store_false', help='Disable DoH.')
    parser.add_argument('--doh-port', type=int, default=None, help='The port for DoH (default: 443).')
    parser.add_argument('--doq', dest='doq', action='store_true', default=None, help='Listen to DNS over QUIC (DoQ). Requires aioquic.')
    parser.add_argument('--no-doq', dest='doq', action='store_false', help='Disable DoQ.')
    parser.add_argument('--doq-port', type=int, default=None, help='The port for DoQ (default: 853).')
    parser.add_argument('--cert', type=str, default=None, help='Path to the TLS certificate file (required for DoT/DoH/DoQ).')
    parser.add_argument('--key', type=str, default=None, help='Path to the TLS private key file (required for DoT/DoH/DoQ).')
    parser.add_argument('--max-log-size', type=int, default=None, help='Maximum log file size in MB.')
    parser.add_argument('--log-file', type=str, default=None, help='Path to the log file (default: dns_log.txt).')
    parser.add_argument('--workers', type=int, default=None, help='Maximum number of threads for processing requests (default: 100).')
    parser.add_argument('--user', type=str, default=None, help='Drop privileges to this user after binding sockets (Linux only).')
    parser.add_argument('--group', type=str, default=None, help='Drop privileges to this group after binding sockets (Linux only). Defaults to the user\'s primary group.')
    args = parser.parse_args()

    config = defaults.copy()
    for k, v in vars(args).items():
        if v is not None:
            config[k] = v

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
    if config['udp']:
        servers.append(DualStackPoolUDPServer((config['host'], config['port']), UDPRequestHandler, max_workers=config['workers']))
    if config['tcp']:
        servers.append(DualStackPoolTCPServer((config['host'], config['port']), TCPRequestHandler, max_workers=config['workers']))
    
    if config['tls']:
        dot_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        dot_context.load_cert_chain(certfile=config['cert'], keyfile=config['key'])
        try:
            dot_context.set_alpn_protocols(['dot'])
        except (AttributeError, NotImplementedError):
            pass
        servers.append(DualStackPoolTCPServer((config['host'], config['tls_port']), DoTRequestHandler, max_workers=config['workers'], ssl_context=dot_context))
        
    if config['doh']:
        doh_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        doh_context.load_cert_chain(certfile=config['cert'], keyfile=config['key'])
        servers.append(DualStackPoolTCPServer((config['host'], config['doh_port']), DoHRequestHandler, max_workers=config['workers'], ssl_context=doh_context))

    doq_ready = None
    if config['doq']:
        doq_ready = threading.Event()
        doq_thread = threading.Thread(target=start_doq_server,
            args=(config['cert'], config['key'], config['host'], config['doq_port'], doq_ready))
        doq_thread.daemon = True
        doq_thread.start()
        if not doq_ready.wait(timeout=10):
            logger.error("DoQ server failed to start within 10 seconds")
            sys.exit(1)

    # All sockets are now bound — safe to drop root privileges
    if config.get('user'):
        drop_privileges(config['user'], config.get('group'), log_file=config.get('log_file'))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)
        thread.daemon = True
        thread.start()
        proto = getattr(s.RequestHandlerClass, 'PROTOCOL_NAME', s.RequestHandlerClass.__name__[:3])
        logger.info("%s server loop running in thread: %s", proto, thread.name)

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Shutting down servers...")
        for s in servers:
            s.shutdown()
            s.server_close()

if __name__ == '__main__':
    main()
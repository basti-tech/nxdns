cat dns_srv_nx.py
#!/usr/bin/python3
import argparse
import sys
import threading
import socketserver
import struct
import datetime
import traceback
import logging
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
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
                                               self.client_address[1]))
        try:
            data = self.get_data()
            logger = logging.getLogger('fake_dns')
            logger.setLevel(logging.DEBUG)
#            fh = logging.FileHandler('dns_log.txt')
#            fh.setLevel(logging.DEBUG)
#            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#            ch = logging.StreamHandler()
#            ch.setLevel(logging.ERROR)
#            fh.setFormatter(formatter)
#            ch.setFormatter(formatter)
#            logger.addHandler(fh)
#            logger.addHandler(ch)
#            logger.info(str(data).replace('\\x', '')[1:-1])
            print(len(data), str(data).replace('\\x', '')[1:-1])
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
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
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

def main():
    parser = argparse.ArgumentParser(description='Start a Fake DNS implemented in Python. Only returns NXDOMAIN and logs requests into a file')
    parser = argparse.ArgumentParser(description='Start a Fake DNS implemented in Python. Only returns NXDOAMIN and logs requests into a file. Usually DNSes use UDP on port 53.')
    parser.add_argument('--port', default=53, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    print("Starting nameserver...")

    servers = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer(('', args.port), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()
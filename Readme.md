# NXDNS - A Python Fake DNS Server

`nxdns` is a simple, lightweight fake DNS server implemented in Python. It is designed to respond to all DNS queries with an `NXDOMAIN` (Non-Existent Domain) response, meaning it tells the client that the requested domain does not exist. 

This is particularly useful for sinkholing, testing network applications, malware analysis, or blocking unwanted traffic.

## Features

- Always returns `NXDOMAIN` for any DNS query.
- Supports both UDP and TCP connections on port 53 (or a custom port).
- Multi-threaded: handles each request in a separate thread.
- Logs all incoming requests (including the requested domain, IP, and protocol) to the console and a file (`dns_log.txt`) with log rotation.

## Requirements

- Python 3.x
- `dnslib` (Can be installed via `pip install dnslib`)

## Usage

You can run the script directly from the command line. Since it binds to port 53 by default, you may need elevated privileges (e.g., `sudo` on Linux/macOS or run as Administrator on Windows) unless you specify a higher port.

```bash
python nxdns.py --udp --tcp
```

### Arguments

- `--port`: The port to listen on (default is `53`).
- `--tcp`: Listen to TCP connections.
- `--udp`: Listen to UDP datagrams.

*Note: You must specify at least one of `--udp` or `--tcp`.*

### Example

Start the server on port 8053 listening only to UDP:
```bash
python nxdns.py --port 8053 --udp
```

## Logging

`nxdns` automatically logs all queries both to standard output and to a local `dns_log.txt` file in the same directory. The log file is automatically rotated when it reaches 5 MB (keeping up to 5 older backups). The log entries include:
- The time of the request
- The protocol used (UDP/TCP)
- The client IP address and port
- The requested domain name (parsed from the raw query)

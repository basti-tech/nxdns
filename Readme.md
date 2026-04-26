# NXDNS - A Python Fake DNS Server

`nxdns` is a simple, lightweight fake DNS server implemented in Python. It is designed to respond to all DNS queries with an `NXDOMAIN` (Non-Existent Domain) response, meaning it tells the client that the requested domain does not exist. 

This is particularly useful for sinkholing, testing network applications, malware analysis, or blocking unwanted traffic.

## Features

- Always returns `NXDOMAIN` for any DNS query.
- Supports both UDP and TCP connections on port 53 (or a custom port).
- Supports DNS over TLS (DoT) on port 853.
- Supports DNS over HTTPS (DoH) on port 443.
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

- `-c`, `--config`: Path to the configuration file (default is `nxdns.conf`).
- `--port`: The port to listen on (default is `53`).
- `--tcp`: Listen to TCP connections.
- `--udp`: Listen to UDP datagrams.
- `--tls`: Listen to DNS over TLS (DoT) connections.
- `--tls-port`: The port for DoT (default is `853`).
- `--doh`: Listen to DNS over HTTPS (DoH) connections.
- `--doh-port`: The port for DoH (default is `443`).
- `--cert`: Path to the TLS certificate (required for `--tls` and `--doh`).
- `--key`: Path to the TLS private key (required for `--tls` and `--doh`).
- `--max-log-size`: Maximum size of the log file in MB before rotation (default is `5`).
- `--log-file`: Path to the log file (default is `dns_log.txt`).

*Note: You must specify at least one of `--udp`, `--tcp`, or `--tls`.*

### Example

Start the server on port 8053 listening only to UDP:
```bash
python nxdns.py --port 8053 --udp
```

Start the server with DoT support:
```bash
python nxdns.py --tls --cert cert.pem --key key.pem
```

## Configuration File

Instead of passing all parameters via the command line, you can use a configuration file (`nxdns.conf`). The server will automatically load `nxdns.conf` if it exists in the same directory, or you can specify one using `-c config_file.conf`. 

Command-line switches will override the configuration file.

Example `nxdns.conf`:
```ini
[nxdns]
port = 53
udp = true
tcp = true
max_log_size = 10
log_file = /var/log/nxdns.log

# TLS Support (DoT)
tls = false
tls_port = 853
cert = cert.pem
key = key.pem

# HTTPS Support (DoH)
doh = false
doh_port = 443
```

## Logging

`nxdns` automatically logs all queries both to standard output and to a local log file (default `dns_log.txt`) in the same directory. The log file is automatically rotated when it reaches the configured max size (keeping up to 5 older backups). The log entries include:
- The time of the request
- The protocol used (UDP/TCP)
- The client IP address and port
- The requested domain name (parsed from the raw query)

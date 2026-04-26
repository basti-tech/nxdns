# NXDNS - A Python Fake DNS Server

`nxdns` is a simple, lightweight fake DNS server implemented in Python. It is designed to respond to all DNS queries with an `NXDOMAIN` (Non-Existent Domain) response, meaning it tells the client that the requested domain does not exist. 

This is particularly useful for sinkholing, testing network applications, malware analysis, or blocking unwanted traffic.

## Features

- Always returns `NXDOMAIN` for any DNS query.
- Supports both UDP and TCP connections on port 53 (or a custom port).
- Supports DNS over TLS (DoT) on port 853.
- Supports DNS over HTTPS (DoH) on port 443.
- Supports DNS over QUIC (DoQ) on port 853.
- Multi-threaded: handles each request in a separate thread.
- Logs all incoming requests (including the requested domain, IP, and protocol) to the console and a file (`dns_log.txt`) with log rotation.

## Requirements & Installation

- Python 3.x

It is highly recommended to install the dependencies in a Python virtual environment (`venv`). To set it up, follow these steps:

1. Create a virtual environment:
   ```bash
   python -m venv venv
   ```

2. Activate the virtual environment:
   - On **Windows**:
     ```bash
     venv\Scripts\activate
     ```
   - On **Linux/macOS**:
     ```bash
     source venv/bin/activate
     ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

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
- `--doq`: Listen to DNS over QUIC (DoQ) connections. (Requires `aioquic` library).
- `--doq-port`: The port for DoQ (default is `853`).
- `--cert`: Path to the TLS certificate (required for `--tls`, `--doh`, and `--doq`).
- `--key`: Path to the TLS private key (required for `--tls`, `--doh`, and `--doq`).
- `--workers`: Maximum number of threads for processing requests (default is `100`). *Recommendation: `100` is perfect for small/home servers. Increase to `200`-`500` for public-facing servers with heavy traffic to mitigate slow-connection exhaustion.*
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

**Note:** The use of CLI switches and the configuration file is mutually exclusive. If you provide any configuration parameters via CLI, the configuration file will be completely ignored.

Example `nxdns.conf`:
```ini
[nxdns]
port = 53
udp = true
tcp = true
workers = 100
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

# QUIC Support (DoQ)
doq = false
doq_port = 853
```

## Testing

You can test the different protocols locally using tools like `dig` (from BIND) and `kdig` (from Knot DNS). 

**Test UDP (Port 53):**
```bash
dig @127.0.0.1 -p 53 example.com
```

**Test TCP (Port 53):**
```bash
dig +tcp @127.0.0.1 -p 53 example.com
```

**Test DoT - DNS over TLS (Port 853):**
*(Note: testing encrypted protocols usually requires valid TLS certificates or skipping validation)*
```bash
kdig -d @127.0.0.1 +tls +tls-host=localhost -p 853 example.com
```

**Test DoH - DNS over HTTPS (Port 443):**
```bash
kdig -d @127.0.0.1 +https=/dns-query -p 443 example.com
```

**Test DoQ - DNS over QUIC (Port 853):**
```bash
kdig -d @127.0.0.1 +quic -p 853 example.com
```

## Logging

`nxdns` automatically logs all queries both to standard output and to a local log file (default `dns_log.txt`) in the same directory. The log file is automatically rotated when it reaches the configured max size (keeping up to 5 older backups). The log entries include:
- The time of the request
- The protocol used (UDP/TCP)
- The client IP address and port
- The requested domain name (parsed from the raw query)

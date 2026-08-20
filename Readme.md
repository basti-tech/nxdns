# NXDNS - A Python Fake DNS Server

`nxdns` is a simple, lightweight, high-performance fake DNS server implemented in Python. It is designed to respond to all DNS queries with an `NXDOMAIN` (Non-Existent Domain) response with the Authoritative Answer (`AA`) flag set, signaling to clients that the requested domain does not exist. 

This is particularly useful for sinkholing, network application testing, malware analysis, ad/tracker blocking, and unwanted traffic isolation.

> **💡 About this Project**: `nxdns` originally started as a personal, hand-crafted Python script for simple DNS sinkholing. With the assistance of AI, the project was modernized and extended to include missing modern features—notably full **DNS over HTTPS (DoH)** and **DNS over QUIC (DoQ)** support, robust threaded connection handling, and automated privilege dropping.


## Features

- **Always NXDOMAIN**: Responds to all valid DNS queries with `NXDOMAIN` (Authoritative Answer `AA=1`).
- **Comprehensive Protocol Support**:
  - Standard **UDP** (default port 53)
  - Standard **TCP** (default port 53) with connection timeouts and message length validation
  - **DNS over TLS (DoT)** (RFC 7858, default port 853)
  - **DNS over HTTPS (DoH)** (RFC 8484, default port 443) with both `GET` and `POST` methods and CORS headers enabled (`Access-Control-Allow-Origin: *`)
  - **DNS over QUIC (DoQ)** (RFC 9250, default port 853, via `aioquic`)
- **IPv4, IPv6 & Dual-Stack**: Full IPv6 and Dual-Stack support when listening on `::` or `""`.
- **Thread Pool Architecture**: Uses a configurable `ThreadPoolExecutor` (`--workers`) for high concurrency and resilience against slow-connection attacks.
- **Security & Privilege Dropping**: Can start as root to bind privileged ports (53, 443, 853) and automatically drop privileges to a dedicated unprivileged user/group (`--user`, `--group`).
- **Logging & Log Rotation**: Logs all queries (timestamp, protocol, client IP/port, query domain and type) to standard output and rotating log files (`dns_log.txt`).

## Requirements & Installation

- Python 3.8+
- Recommended: Virtual environment (`venv`)

### Setup

1. **Create and activate a virtual environment:**
   - **Linux / macOS:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
   - **Windows:**
     ```bash
     python -m venv venv
     venv\Scripts\activate
     ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

*(Optional: `aioquic` is required only if you enable DNS over QUIC (`--doq`).)*

## Usage

Start the server using CLI arguments or a configuration file. Since binding to ports below 1024 requires root privileges on Linux/macOS, run with `sudo` (or as Administrator on Windows), or specify custom non-privileged ports for testing.

```bash
# Basic UDP + TCP server
python nxdns.py --udp --tcp
```

### CLI Arguments

| Argument | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-c`, `--config` | string | `nxdns.conf` | Path to custom configuration file |
| `--host` | string | `127.0.0.1` | Interface to listen on. Use `::` or `""` for DualStack (IPv4+IPv6) |
| `--port` | integer | `53` | Standard DNS port for UDP and TCP |
| `--udp` | flag | `false` | Enable standard UDP listener |
| `--tcp` | flag | `false` | Enable standard TCP listener |
| `--tls` | flag | `false` | Enable DNS over TLS (DoT) |
| `--tls-port` | integer | `853` | Port for DoT listener |
| `--doh` | flag | `false` | Enable DNS over HTTPS (DoH) |
| `--doh-port` | integer | `443` | Port for DoH listener |
| `--doq` | flag | `false` | Enable DNS over QUIC (DoQ) |
| `--doq-port` | integer | `853` | Port for DoQ listener |
| `--cert` | string | `None` | Path to TLS certificate file (required for DoT, DoH, DoQ) |
| `--key` | string | `None` | Path to TLS private key file (required for DoT, DoH, DoQ) |
| `--workers` | integer | `100` | Max worker threads for handling concurrent queries |
| `--max-log-size` | integer | `5` | Max log file size in MB before rotation (keeps up to 5 backups) |
| `--log-file` | string | `dns_log.txt` | Path to output log file |
| `--user` | string | `None` | Drop root privileges to this system user after socket binding (Linux only) |
| `--group` | string | `None` | Drop root privileges to this group after socket binding (Linux only) |

> **Note:** You must enable at least one protocol: `--udp`, `--tcp`, `--tls`, `--doh`, or `--doq`.

### CLI Examples

**Run UDP and TCP on a high port (no root required):**
```bash
python nxdns.py --udp --tcp --port 8053
```

**Run all encrypted protocols (DoT, DoH, DoQ) with certificates:**
```bash
sudo python nxdns.py --tls --doh --doq --cert /etc/ssl/certs/server.crt --key /etc/ssl/private/server.key --user nxdns
```

**Run full Dual-Stack (IPv4 + IPv6) on all interfaces:**
```bash
sudo python nxdns.py --host "::" --udp --tcp --user nxdns
```

---

## Configuration File

Instead of command-line flags, you can configure `nxdns` via `nxdns.conf`. If `nxdns.conf` exists in the working directory (or is specified with `-c <file>`), it will be loaded automatically if no CLI options (other than `-c`) are given.

### Example `nxdns.conf`

```ini
[nxdns]
# Interface: use 127.0.0.1 for localhost, or :: for all IPv4/IPv6 interfaces
host = 127.0.0.1
port = 53

# Protocols to enable
udp = true
tcp = true

# Concurrency & Logging
workers = 100
max_log_size = 5
log_file = dns_log.txt

# Privilege dropping (Linux only - highly recommended for production)
# user = nxdns
# group = nxdns

# TLS Certificates (Required for DoT, DoH, DoQ)
# cert = cert.pem
# key = key.pem

# Encrypted Protocols
# tls = false
# tls_port = 853
# doh = false
# doh_port = 443
# doq = false
# doq_port = 853
```

---

## Testing

Verify that your `nxdns` server responds with `NXDOMAIN` across enabled protocols using standard tools.

### 1. Test UDP (Port 53)
```bash
dig @127.0.0.1 -p 53 example.com
```
*Expected: `status: NXDOMAIN` and `flags: qr aa rd`*

### 2. Test TCP (Port 53)
```bash
dig +tcp @127.0.0.1 -p 53 example.com
```
*Expected: `status: NXDOMAIN`*

### 3. Test DNS over TLS (DoT - Port 853)
```bash
kdig -d @127.0.0.1 +tls +tls-host=localhost -p 853 example.com
```

### 4. Test DNS over HTTPS (DoH - Port 443)

#### GET Query (URL Parameter / Base64url)
```bash
curl -k -i "https://127.0.0.1:443/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
```
*Expected: `HTTP/1.0 200 OK`, `content-type: application/dns-message`, `access-control-allow-origin: *`*

#### POST Query (Raw DNS Message Body)
```bash
python -c "import urllib.request, ssl, dnslib; q = dnslib.DNSRecord.question('example.com').pack(); req = urllib.request.Request('https://127.0.0.1:443/dns-query', data=q, headers={'Content-Type': 'application/dns-message'}); ctx = ssl._create_unverified_context(); res = dnslib.DNSRecord.parse(urllib.request.urlopen(req, context=ctx).read()); print(f'RCODE: {dnslib.RCODE[res.header.rcode]}')"
```
*Expected: `RCODE: NXDOMAIN`*

#### CORS Preflight (OPTIONS)
```bash
curl -k -i -X OPTIONS "https://127.0.0.1:443/dns-query"
```
*Expected: `HTTP/1.0 204 No Content` with CORS headers.*

### 5. Test DNS over QUIC (DoQ - Port 853)
```bash
kdig -d @127.0.0.1 +quic -p 853 example.com
```
*Expected: `status: NXDOMAIN`*

---

## Security & Production Deployment

### Automatic Privilege Dropping

Binding standard DNS ports (53, 443, 853) requires elevated permissions (`root`). Running the entire application as `root` is a security risk. `nxdns` supports automatic privilege de-escalation:

1. Create a non-privileged system user:
   ```bash
   sudo useradd --system --no-create-home --shell /sbin/nologin nxdns
   sudo touch /var/log/dns_log.txt
   sudo chown nxdns:nxdns /var/log/dns_log.txt
   ```

2. Start `nxdns` specifying `--user`:
   ```bash
   sudo python nxdns.py --udp --tcp --log-file /var/log/dns_log.txt --user nxdns
   ```

`nxdns` binds all network sockets (UDP, TCP, TLS, and QUIC) as `root`, then immediately drops privileges to the specified user before entering the request handling loop.

### Systemd Service Example

Create `/etc/systemd/system/nxdns.service`:

```ini
[Unit]
Description=NXDNS Fake DNS Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/nxdns
ExecStart=/opt/nxdns/venv/bin/python nxdns.py --config /opt/nxdns/nxdns.conf
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Logging

`nxdns` logs every received query with the following information:
- **Timestamp**: Date and time of the query
- **Protocol**: Protocol used (`UDP`, `TCP`, `DoH`, `DoQ`)
- **Client**: Client IP address and source port
- **Query**: Requested domain name and record type (e.g., `example.com. (A)`)

Example log output:
```text
2026-08-20 08:00:00,123 - INFO - UDP request from 192.168.1.50:54321 for example.com. (A)
2026-08-20 08:00:01,456 - INFO - DoH request from 192.168.1.55:61234 for telemetry.badactor.com. (AAAA)
```

Rotated log backups are automatically maintained up to 5 history files when `--max-log-size` is exceeded.

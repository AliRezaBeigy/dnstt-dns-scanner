# dnstt-dns-scanner

[![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub Release](https://img.shields.io/github/release/AliRezaBeigy/dnstt-dns-scanner.svg)](https://github.com/AliRezaBeigy/dnstt-dns-scanner/releases)

A powerful tool to scan IP address ranges and discover DNS servers that can be used with [`dnstt-client`](https://github.com/Mygod/dnstt). This scanner helps you find working DNS resolvers that support the dnstt (DNS tunnel) protocol, including full SOCKS proxy functionality.

## Features

- 🔍 **Comprehensive DNS Testing** - Tests basic DNS functionality, EDNS(0) support, and dnstt encoding compatibility
- 🚀 **Full Tunnel Verification** - Verifies complete tunnel connectivity including SOCKS5 proxy support (as deployed by [dnstt-deploy](https://github.com/bugfloyd/dnstt-deploy))
- ⚡ **High Performance** - Multi-threaded scanning with configurable concurrency
- 📊 **Detailed Reporting** - Shows latency, capabilities, and provides ready-to-use commands
- 💾 **Export Results** - Save scan results to file with metadata and commands
- 🎯 **CIDR Support** - Scan entire network ranges efficiently
- 🔄 **Graceful Interruption** - Press Ctrl+C to stop and see partial results

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
  - [Pre-built Binaries](#pre-built-binaries)
  - [From Source](#from-source)
- [Usage](#usage)
  - [Options](#options)
  - [Examples](#examples)
- [How It Works](#how-it-works)
- [Output](#output)
  - [Status Tags](#status-tags)
- [Building](#building)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Requirements

- **dnstt server** - Required for dnstt and tunnel verification
- **dnstt-deploy with SOCKS mode** - The tunnel check (`TUNNEL` tag) requires a dnstt server deployed with SOCKS proxy support (as provided by [dnstt-deploy](https://github.com/bugfloyd/dnstt-deploy) in SOCKS mode). Without this, only basic DNS and DNSTT encoding tests will pass.

## Installation

### Pre-built Binaries

Download pre-built binaries from the [Releases](https://github.com/AliRezaBeigy/dnstt-dns-scanner/releases) page:

- **Linux**: [`dnstt-dns-scanner-linux-amd64`](https://github.com/AliRezaBeigy/dnstt-dns-scanner/releases/latest/download/dnstt-dns-scanner-linux-amd64), [`dnstt-dns-scanner-linux-arm64`](https://github.com/AliRezaBeigy/dnstt-dns-scanner/releases/latest/download/dnstt-dns-scanner-linux-arm64)
- **Windows**: [`dnstt-dns-scanner-windows-amd64.exe`](https://github.com/AliRezaBeigy/dnstt-dns-scanner/releases/latest/download/dnstt-dns-scanner-windows-amd64.exe)
- **macOS**: [`dnstt-dns-scanner-darwin-amd64`](https://github.com/AliRezaBeigy/dnstt-dns-scanner/releases/latest/download/dnstt-dns-scanner-darwin-amd64), [`dnstt-dns-scanner-darwin-arm64`](https://github.com/AliRezaBeigy/dnstt-dns-scanner/releases/latest/download/dnstt-dns-scanner-darwin-arm64)

After downloading, extract and make executable (Linux/macOS):
```bash
chmod +x dnstt-dns-scanner
```

### From Source

```bash
git clone https://github.com/AliRezaBeigy/dnstt-dns-scanner.git
cd dnstt-dns-scanner
go mod download
cd dnstt-dns-scanner
go build -o dnstt-dns-scanner main.go
```

## Usage

```
dnstt-dns-scanner -ips IP_OR_CIDR_OR_FILE (-pubkey PUBKEY|-pubkey-file PUBKEYFILE) DOMAIN [OPTIONS]
```

The `-ips` flag accepts:
- **CIDR notation** (e.g., `192.168.1.0/24`, `10.10.0.0/16`)
- **Single IP address** (e.g., `192.168.1.1`)
- **File path** containing IPs or CIDRs (one per line, `#` for comments)

### Options

| Option | Description | Required |
|--------|-------------|----------|
| `-ips IP_OR_CIDR_OR_FILE` | IP address, CIDR notation, or file path containing IPs/CIDRs (one per line) | ✅ Yes |
| `-pubkey PUBKEY` | Server public key as hexadecimal string (64 hex digits) | ⚠️ One of |
| `-pubkey-file FILE` | Path to file containing server public key | ⚠️ One of |
| `DOMAIN` | The DNS domain used by the tunnel (e.g., `t.example.com`) | ✅ Yes |
| `-threads N` | Number of concurrent scanning threads (default: `50`) | ❌ No |
| `-timeout DURATION` | Timeout for each DNS query (default: `10s`, e.g., `5s`, `2m`) | ❌ No |
| `-verbose` | Show all results including failures | ❌ No |
| `-output FILE` | Save results to file (includes summary and ready-to-use commands) | ❌ No |
| `-test-domain DOMAIN` | Custom domain to query for DNS server test | ❌ No |
| `-test-txt VALUE` | Expected TXT record value to verify DNS server works correctly | ❌ No |
| `-quick` | Skip advanced tunnel tests (only perform basic connectivity test) | ❌ No |

### Examples

**Scan a single IP address:**
```bash
./dnstt-dns-scanner -ips 192.168.1.1 \
                     -pubkey-file server.pub \
                     t.example.com
```

**Scan a CIDR network range:**
```bash
./dnstt-dns-scanner -ips 192.168.1.0/24 \
                     -pubkey-file server.pub \
                     t.example.com
```

**Scan from a file containing IPs/CIDRs:**
```bash
# Create ip-list.txt with:
# 192.168.1.1
# 192.168.1.0/24
# 10.10.0.0/16
# # Comments are supported

./dnstt-dns-scanner -ips ip-list.txt \
                     -pubkey-file server.pub \
                     t.example.com \
                     -output results.txt
```

**High-performance scan with 100 threads:**
```bash
./dnstt-dns-scanner -ips 10.10.0.0/16 \
                     -pubkey-file server.pub \
                     t.example.com \
                     -threads 100
```

**Scan with custom timeout and save results:**
```bash
./dnstt-dns-scanner -ips 192.168.1.0/24 \
                     -pubkey 0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff \
                     t.example.com \
                     -timeout 5s \
                     -output results.txt
```

**Verbose scan with custom test domain:**
```bash
./dnstt-dns-scanner -ips 10.0.0.0/8 \
                     -pubkey-file server.pub \
                     t.example.com \
                     -threads 200 \
                     -timeout 5s \
                     -verbose \
                     -test-domain test.k.markop.ir \
                     -test-txt "TEST RESULT" \
                     -output scan_results.txt
```

**Quick scan (basic connectivity only, faster):**
```bash
./dnstt-dns-scanner -ips 10.10.0.0/16 \
                     -pubkey-file server.pub \
                     t.example.com \
                     -quick
```

## How It Works

The scanner performs a comprehensive three-stage test for each DNS server:

1. **Basic DNS Test** - Sends a DNS query and verifies:
   - Valid DNS response format
   - Response ID matches query ID
   - EDNS(0) support detection

2. **DNSTT Encoding Test** - Verifies the server can handle dnstt-encoded queries:
   - Establishes DNS packet connection
   - Tests KCP protocol over DNS
   - Verifies Noise handshake capability

3. **Full Tunnel Test** - Complete end-to-end verification:
   - Establishes full protocol stack: DNS → KCP → Noise → smux
   - Tests SOCKS5 proxy connectivity
   - Verifies HTTP traffic routing through tunnel
   - **Only servers passing this test receive the `TUNNEL` tag**

### Test Modes

**Full Mode (default):** Performs all tunnel tests including:
- Basic connectivity test (single HTTP request)
- Multiple concurrent streams test
- Sustained data transfer test
- Multiple streams stability test
- **Bidirectional communication test** (8 request/response cycles to catch DNS resolvers that stop mid-connection)

**Quick Mode (`-quick` flag):** Only performs the basic connectivity test. This is faster but may miss DNS resolvers that work initially but fail under sustained use (like SSH authentication failures). Use quick mode for initial scanning, then verify promising servers with full mode.

## Output

The scanner provides real-time feedback and comprehensive results:

- ✅ **Live Results** - Working servers are printed as they're discovered
- 📈 **Progress Updates** - Shows progress every 1000 IPs or 10% (whichever is smaller)
- 📋 **Summary Statistics** - Total scanned, working servers, and capability breakdown
- 🔧 **Ready-to-Use Commands** - Copy-paste `dnstt-client` commands for each working server

### Status Tags

Each discovered DNS server shows status tags indicating its capabilities:

| Tag | Meaning | Importance |
|-----|---------|------------|
| `EDNS` | Server supports EDNS(0) extension | Preferred for better performance |
| `DNSTT` | Server can handle dnstt-encoded queries | Required for dnstt tunneling |
| `TUNNEL` | **Complete tunnel established** with SOCKS proxy support | ⭐ **Essential** - Only servers with this tag work for actual tunneling |

**⚠️ Important**: The `TUNNEL` tag indicates that the DNS server can successfully establish a complete dnstt tunnel connection, including SOCKS proxy functionality (as deployed by [dnstt-deploy](https://github.com/bugfloyd/dnstt-deploy)). This means the server can:

- Accept dnstt-encoded DNS queries
- Establish a full tunnel connection (DNS → KCP → Noise → smux)
- Route traffic through the SOCKS5 proxy interface (typically `127.0.0.1:1080`)

**Only servers with the `TUNNEL` tag are fully functional for dnstt tunneling with SOCKS proxy support.** Servers without `TUNNEL` can respond to DNS queries but cannot complete the tunnel connection to your dnstt server or route traffic through SOCKS.


## Building

### Prerequisites

- Go 1.21 or later
- Git (for dependency management)

### Build Steps

```bash
git clone https://github.com/AliRezaBeigy/dnstt-dns-scanner.git
cd dnstt-dns-scanner
go mod download
cd dnstt-dns-scanner
go build -o dnstt-dns-scanner main.go
```

Or install directly:
```bash
cd dnstt-dns-scanner
go install
```

## Troubleshooting

### No servers found with TUNNEL tag

- **Verify your public key** - Ensure you're using the correct public key for your dnstt server
- **Check domain configuration** - Verify the domain is correctly configured for dnstt
- **Test connectivity** - Ensure the DNS servers can reach your dnstt tunnel server
- **Increase timeout** - Try `-timeout 30s` for slower networks

### Build errors

- **Go version** - Ensure you have Go 1.21+ installed (`go version`)
- **Dependencies** - Run `go mod download` to fetch dependencies
- **Network access** - Ensure you can access GitHub for dependency downloads

### Slow scanning

- **Increase threads** - Use `-threads 100` or higher (be mindful of network limits)
- **Reduce timeout** - Lower timeout for faster failures (e.g., `-timeout 5s`)
- **Smaller ranges** - Start with `/24` ranges before scanning larger networks

### Permission denied (Linux/macOS)

```bash
chmod +x dnstt-dns-scanner
```

## Related Projects

- [dnstt](https://github.com/Mygod/dnstt) - DNS tunnel implementation
- [dnstt-deploy](https://github.com/bugfloyd/dnstt-deploy) - One-click dnstt server deployment

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Made with ❤️ for the dnstt community**

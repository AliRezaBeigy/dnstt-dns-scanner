# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.1] - 2026-03-02

### Changed
- Output file (`-output`) now matches stdout: same tunnel-capable section (headers, detailed list, and IP list) is written to the file
- File output contains only tunnel-capable DNS servers (no metadata header or non-tunnel IPs)

## [1.2.0] - 2026-03-02

### Added
- `-tunnel-only` flag to filter live output to only show DNS servers with full tunnel support (`[TUNNEL]` tag)
- Post-scan stdout now prints a detailed list of tunnel-capable servers sorted by latency, followed by a plain IP-only list
- Per-test latency breakdown in post-scan output: basic HTTP, second stream, data transfer, multi-stream, and bidirectional

### Changed
- File output (`-output`) simplified to plain IPs only — removed redundant `dnstt-client` command lines
- File output IPs sorted by latency (fastest first)
- Progress counter uses "Tunnel servers" label instead of "Found" when `-tunnel-only` is active

### Removed
- Post-scan `dnstt-client` command dump from stdout (use `-output` to save IPs to file)

## [1.1.0] - 2026-01-23

### Added
- `-quick` flag to skip advanced tunnel tests and only perform basic connectivity test
- Extended full tunnel test suite with multiple concurrent stream tests
- 2 KB sustained data transfer test to verify throughput
- Multiple stream stability test (3 rapid streams)
- Bidirectional communication test (8 request/response cycles) to catch resolvers that drop under sustained load

### Changed
- Default scan mode now runs all five tunnel tests for higher confidence results

## [1.0.0] - 2026-01-20

### Added
- Initial release
- Multi-threaded IP/CIDR range scanning with configurable concurrency (`-threads`)
- Three-stage DNS server testing: basic DNS, DNSTT encoding, full tunnel verification
- EDNS(0) support detection
- Full tunnel stack verification (DNS → KCP → Noise → smux → SOCKS5)
- Status tags in live output: `[EDNS]`, `[DNSTT]`, `[TUNNEL]`
- Real-time progress updates to stderr
- Final summary statistics to stderr
- File export with metadata header (`-output`)
- IP input from single address, CIDR notation, or file with mixed entries
- Custom test domain and expected TXT value flags (`-test-domain`, `-test-txt`)
- `-verbose` flag to show failed servers on stderr
- Graceful Ctrl+C interruption with partial results

[Unreleased]: https://github.com/AliRezaBeigy/dnstt-dns-scanner/compare/v1.2.1...HEAD
[1.2.1]: https://github.com/AliRezaBeigy/dnstt-dns-scanner/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/AliRezaBeigy/dnstt-dns-scanner/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/AliRezaBeigy/dnstt-dns-scanner/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/AliRezaBeigy/dnstt-dns-scanner/releases/tag/v1.0.0

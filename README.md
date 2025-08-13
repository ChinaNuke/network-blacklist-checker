# Network Blacklist Checker

A network security analysis tool for examining PCAP files to identify potential malicious activity through TCP reset packet analysis and DNS correlation.

## Features

- Extract source IP addresses from TCP reset packets
- Correlate IP addresses with DNS queries to identify domain names
- Useful for network security analysis and threat detection

## Installation

This project uses [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
# Install dependencies
uv sync

# Or run directly with uv
uv run python pcap_analyzer.py <pcap_file>
```

## Usage

```bash
uv run python pcap_analyzer.py path/to/your/capture.pcap
```

### Example Output

```
Extracting source IPs from TCP reset packets...
Loaded 13278 packets from ~/wechat.pcapng
Found 5 unique IPs that sent TCP reset packets

Extracting DNS A record mappings...
Found 70 DNS A record mappings

============================================================
DOMAIN NAME -> IP ADDRESS MAPPINGS FOR RESET SOURCES
============================================================
<no DNS mapping found>                   -> 109.244.228.251
mp.weixin.qq.com                         -> 140.207.191.167
<no DNS mapping found>                   -> 172.207.123.2
<no DNS mapping found>                   -> 192.168.209.46
res.wx.qq.com                            -> 43.141.69.176

============================================================
Summary: 2/5 reset IPs have corresponding DNS mappings
```

## Requirements

- Python 3.13+
- scapy (automatically installed via uv)

## License

This tool is intended for defensive security analysis only.
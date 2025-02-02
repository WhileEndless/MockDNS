#!/usr/bin/env python3

import argparse
import json
import logging
import signal
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from rich.panel import Panel
from rich.box import SIMPLE, ROUNDED
from rich.live import Live
import logging.handlers
import dns.resolver
import dns.rdatatype
import dns.rdataclass
import ipaddress

def decode_domain_name(data: bytes, offset: int) -> (str, int):
    labels = []
    jumped = False
    original_offset = offset
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        else:
            offset += 1
            labels.append(data[offset:offset+length].decode('utf-8'))
            offset += length
    return '.'.join(labels), (original_offset if jumped else offset)

def encode_domain_name(domain: str) -> bytes:
    result = bytearray()
    for part in domain.split('.'):
        result.append(len(part))
        result.extend(part.encode('utf-8'))
    result.append(0)
    return bytes(result)

@dataclass
class DNSStats:
    start_time: datetime = field(default_factory=datetime.now)
    total_queries: int = 0
    query_types: Dict[str, int] = field(default_factory=dict)
    client_ips: Dict[str, int] = field(default_factory=dict)
    host_queries: Dict[str, int] = field(default_factory=dict)

@dataclass
class DNSRecord:
    name: str
    type: str
    ttl: int = 60
    data: Any = None
    not_found: bool = False

@dataclass
class CacheEntry:
    records: List[DNSRecord]
    expires_at: Optional[datetime]

@dataclass
class DNSSettings:
    default_dns_servers: List[str]
    fallback_ips: Optional[Dict[str, str]]
    enable_fallback: bool
    ttl: int
    enable_recursive_query: bool
    enable_cache: bool
    cache_ttl: int

    @classmethod
    def from_dict(cls, data: dict):
        enable_fallback = data.get('enable_fallback', False)
        fallback_ips = data.get('fallback_ips')
        if enable_fallback and not fallback_ips:
            fallback_ips = {
                "A": "127.0.0.1",
                "AAAA": "::1"
            }
        return cls(
            default_dns_servers=data.get('default_dns_servers', ['8.8.8.8']),
            fallback_ips=fallback_ips,
            enable_fallback=enable_fallback,
            ttl=data.get('ttl', 60),
            enable_recursive_query=data.get('enable_recursive_query', False),
            enable_cache=data.get('enable_cache', True),
            cache_ttl=data.get('cache_ttl', 600)
        )

@dataclass
class DNSServer:
    host: str
    port: int
    records_file: Path
    log_file: Optional[Path]
    records: Dict[str, Any] = field(default_factory=dict)
    stats: DNSStats = field(default_factory=DNSStats)
    console: Console = field(default_factory=Console)
    settings: Optional[DNSSettings] = None
    cache: Dict[tuple, CacheEntry] = field(default_factory=dict)
    query_table: Table = field(default_factory=lambda: Table(box=SIMPLE, show_header=True, header_style="bold cyan"))
    live_display: Live = None

    QTYPE_A = b'\x00\x01'
    QTYPE_AAAA = b'\x00\x1c'
    QTYPE_MX = b'\x00\x0f'
    QTYPE_CNAME = b'\x00\x05'

    def __post_init__(self):
        self.query_table.add_column("Time", style="dim")
        self.query_table.add_column("Query", style="yellow")
        self.query_table.add_column("Type", style="magenta")
        self.query_table.add_column("Client", style="blue")
        self.query_table.add_column("Source", style="green")
        self.query_table.add_column("Result", style="cyan")
        self.query_table.add_column("TTL", style="dim cyan")
        self.live_display = Live(self.query_table, auto_refresh=False)
        self.setup_logging()
        self.load_records()

    def load_records(self):
        try:
            data = json.loads(self.records_file.read_text())
            self.settings = DNSSettings.from_dict(data.get('settings', {}))
            self.records = data.get('records', {})
            logging.info(f"Loaded {len(self.records)} DNS records from {self.records_file}")
        except Exception as e:
            logging.error(f"Failed to load records from {self.records_file}: {e}")
            sys.exit(1)

    def setup_logging(self):
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        if self.log_file:
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler = logging.handlers.RotatingFileHandler(
                self.log_file,
                maxBytes=10*1024*1024,
                backupCount=5
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        else:
            console_handler = RichHandler()
            logger.addHandler(console_handler)

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((self.host, self.port))
            self.console.print("\n")
            summary = Table(title="DNS Server Configuration", box=ROUNDED, show_header=False)
            summary.add_column("Setting", style="cyan", width=25)
            summary.add_column("Value", style="green")
            summary.add_row("Bind Address", f"{self.host}:{self.port}")
            summary.add_row("Records File", str(self.records_file))
            if self.log_file:
                summary.add_row("Log File", str(self.log_file))
            summary.add_row("Recursive Query", "✓ Enabled" if self.settings.enable_recursive_query else "✗ Disabled")
            summary.add_row("DNS Servers", ", ".join(self.settings.default_dns_servers))
            summary.add_row("Default TTL", f"{self.settings.ttl} seconds")
            summary.add_row("Fallback Resolution", "✓ Enabled" if self.settings.enable_fallback else "✗ Disabled")
            if self.settings.enable_fallback and self.settings.fallback_ips:
                fallback_ips = [f"{type_}: {ip}" for type_, ip in self.settings.fallback_ips.items()]
                summary.add_row("Fallback IPs", "\n".join(fallback_ips))
            summary.add_row("Cache", "✓ Enabled" if self.settings.enable_cache else "✗ Disabled")
            if self.settings.enable_cache:
                cache_ttl = "Unlimited" if self.settings.cache_ttl == -1 else f"{self.settings.cache_ttl} seconds"
                summary.add_row("Cache TTL", cache_ttl)
            self.console.print("\n")
            self.console.print(Panel(summary))
            if self.records:
                records_table = Table(title="Local DNS Records", box=ROUNDED)
                records_table.add_column("Domain", style="cyan")
                records_table.add_column("Record Types", style="yellow")
                records_table.add_column("TTL", style="green")
                for domain, data in self.records.items():
                    record_types = [rt for rt in data.keys() if rt != 'TTL']
                    ttl = data.get('TTL', self.settings.ttl)
                    records_table.add_row(domain, ", ".join(record_types), f"{ttl}s")
                self.console.print("\n")
                self.console.print(Panel(records_table))
            self.console.print("\n[bold green]Server is ready to handle DNS queries![/bold green]")
            self.console.print("[dim]Query History:[/dim]")
            with self.live_display:
                while True:
                    data, addr = sock.recvfrom(512)
                    self.handle_query(data, addr, sock)
        except KeyboardInterrupt:
            self.live_display.stop()
            query_rows = [row for row in self.query_table.rows]
            self.console.clear()
            self.show_stats(query_rows, show_history=False)
            self.console.print("\n[bold blue]Query History[/bold blue]")
            self.console.print("=" * 50)
            history_table = self._create_history_table(query_rows)
            self.console.print(history_table)
        except Exception as e:
            logging.error(f"Server error: {e}")
        finally:
            sock.close()

    def get_record_data(self, domain: str, qtype: bytes) -> Optional[List[DNSRecord]]:
        record_type = self._qtype_to_string(qtype)
        cache_key = (domain, record_type)
        if self.settings.enable_cache:
            cached = self._get_from_cache(cache_key)
            if cached:
                if cached[0].not_found:
                    logging.info(f"Negative cache hit: {domain} ({record_type})")
                    return None
                logging.info(f"Cache hit: {domain} ({record_type})")
                return cached
        records = []
        if domain in self.records:
            records.extend(self._get_records_for_domain(domain, qtype))
        if not records:
            wildcard_match = self._find_wildcard_match(domain)
            if wildcard_match:
                records.extend(self._get_records_for_domain(wildcard_match, qtype))
        if not records and self.settings.enable_recursive_query:
            recursive_result = self._perform_recursive_query(domain, qtype)
            if recursive_result:
                records.extend(recursive_result)
                if self.settings.enable_cache:
                    self._add_to_cache(cache_key, recursive_result)
        if not records and self.settings.enable_fallback:
            fallback_record = self._get_fallback_record(domain, qtype)
            if fallback_record:
                records.append(fallback_record)
        if not records and self.settings.enable_cache:
            not_found_record = DNSRecord(
                name=domain,
                type=record_type,
                ttl=min(self.settings.ttl, 300),
                not_found=True
            )
            self._add_to_cache(cache_key, [not_found_record])
            logging.info(f"Added negative cache entry: {domain} ({record_type})")
        return records if records else None

    def _get_records_for_domain(self, domain: str, qtype: bytes) -> List[DNSRecord]:
        records = []
        domain_data = self.records[domain]
        ttl = domain_data.get('TTL', self.settings.ttl)
        record_type = self._qtype_to_string(qtype)
        if record_type in domain_data:
            data = domain_data[record_type]
            if isinstance(data, list):
                for item in data:
                    records.append(DNSRecord(domain, record_type, ttl, item))
            else:
                records.append(DNSRecord(domain, record_type, ttl, data))
        return records

    def _find_wildcard_match(self, domain: str) -> Optional[str]:
        domain_parts = domain.split('.')
        for i in range(len(domain_parts)):
            wildcard = f"*.{'.'.join(domain_parts[i:])}"
            if wildcard in self.records:
                return wildcard
        return None

    def _perform_recursive_query(self, domain: str, qtype: bytes) -> Optional[List[DNSRecord]]:
        resolver = dns.resolver.Resolver()
        rdtype = {
            self.QTYPE_A: dns.rdatatype.A,
            self.QTYPE_AAAA: dns.rdatatype.AAAA,
            self.QTYPE_MX: dns.rdatatype.MX,
            self.QTYPE_CNAME: dns.rdatatype.CNAME
        }.get(qtype, dns.rdatatype.A)
        for dns_server in self.settings.default_dns_servers:
            try:
                resolver.nameservers = [dns_server]
                logging.info(f"Querying external DNS: {dns_server} for {domain}")
                answers = resolver.resolve(domain, rdtype)
                records = []
                for answer in answers:
                    if rdtype == dns.rdatatype.A:
                        records.append(DNSRecord(domain, "A", self.settings.ttl, str(answer)))
                    elif rdtype == dns.rdatatype.AAAA:
                        records.append(DNSRecord(domain, "AAAA", self.settings.ttl, str(answer)))
                    elif rdtype == dns.rdatatype.MX:
                        records.append(DNSRecord(domain, "MX", self.settings.ttl, {
                            "preference": answer.preference,
                            "exchange": str(answer.exchange)
                        }))
                    elif rdtype == dns.rdatatype.CNAME:
                        records.append(DNSRecord(domain, "CNAME", self.settings.ttl, str(answer)))
                if records:
                    logging.info(f"Found {len(records)} record(s) from {dns_server}")
                    return records
            except Exception as e:
                logging.error(f"Query failed to {dns_server}: {e}")
                continue
        return None

    def _get_fallback_record(self, domain: str, qtype: bytes) -> Optional[DNSRecord]:
        record_type = self._qtype_to_string(qtype)
        if self.settings.fallback_ips and record_type in self.settings.fallback_ips:
            fallback_ip = self.settings.fallback_ips[record_type]
            logging.info(f"Using fallback IP: {fallback_ip} for {domain}")
            return DNSRecord(domain, record_type, self.settings.ttl, fallback_ip)
        return None

    def _qtype_to_string(self, qtype: bytes) -> str:
        qtype_map = {
            self.QTYPE_A: "A",
            self.QTYPE_AAAA: "AAAA",
            self.QTYPE_MX: "MX",
            self.QTYPE_CNAME: "CNAME"
        }
        return qtype_map.get(qtype, "A")

    def add_answer_records(self, response: bytearray, records: List[DNSRecord], question_offset: int):
        for record in records:
            pointer = 0xC000 | question_offset
            response.extend(pointer.to_bytes(2, 'big'))
            if record.type == "A":
                response.extend(self.QTYPE_A)
                response.extend(b'\x00\x01')
                response.extend(record.ttl.to_bytes(4, 'big'))
                response.extend(b'\x00\x04')
                for part in record.data.split('.'):
                    response.append(int(part))
            elif record.type == "AAAA":
                response.extend(self.QTYPE_AAAA)
                response.extend(b'\x00\x01')
                response.extend(record.ttl.to_bytes(4, 'big'))
                response.extend(b'\x00\x10')
                try:
                    ipv6_addr = ipaddress.IPv6Address(record.data)
                    response.extend(ipv6_addr.packed)
                except Exception as e:
                    logging.error(f"Invalid IPv6 address {record.data} for {record.name}: {e}")
            elif record.type == "MX":
                response.extend(self.QTYPE_MX)
                response.extend(b'\x00\x01')
                response.extend(record.ttl.to_bytes(4, 'big'))
                mx_data = encode_domain_name(record.data["exchange"])
                rdlength = 2 + len(mx_data)
                response.extend(rdlength.to_bytes(2, 'big'))
                response.extend(record.data["preference"].to_bytes(2, 'big'))
                response.extend(mx_data)
            elif record.type == "CNAME":
                response.extend(self.QTYPE_CNAME)
                response.extend(b'\x00\x01')
                response.extend(record.ttl.to_bytes(4, 'big'))
                cname_data = encode_domain_name(record.data)
                rdlength = len(cname_data)
                response.extend(rdlength.to_bytes(2, 'big'))
                response.extend(cname_data)

    def handle_query(self, data: bytes, addr: tuple, sock: socket.socket):
        try:
            self.stats.total_queries += 1
            client_ip = addr[0]
            self.stats.client_ips[client_ip] = self.stats.client_ips.get(client_ip, 0) + 1

            if len(data) < 12:
                return

            query_id = data[0:2]
            domain, offset = decode_domain_name(data, 12)
            if offset + 4 > len(data):
                return
            qtype = data[offset:offset+2]
            qclass = data[offset+2:offset+4]
            question_offset = 12

            self.stats.host_queries[domain] = self.stats.host_queries.get(domain, 0) + 1

            current_time = datetime.now().strftime("%H:%M:%S")
            source = ""
            records = None

            cache_key = (domain, self._qtype_to_string(qtype))
            if self.settings.enable_cache:
                cached = self._get_from_cache(cache_key)
                if cached:
                    records = cached
                    source = "Cache"

            if not records:
                if domain in self.records:
                    records = self._get_records_for_domain(domain, qtype)
                    source = "Local"
                if not records:
                    wildcard = self._find_wildcard_match(domain)
                    if wildcard:
                        records = self._get_records_for_domain(wildcard, qtype)
                        source = "Wildcard"
                if not records and self.settings.enable_recursive_query:
                    records = self._perform_recursive_query(domain, qtype)
                    if records:
                        source = "External DNS"
                        if self.settings.enable_cache:
                            self._add_to_cache(cache_key, records)
                if not records and self.settings.enable_fallback:
                    fallback = self._get_fallback_record(domain, qtype)
                    if fallback:
                        records = [fallback]
                        source = "Fallback"

            if records:
                results = []
                ttls = []
                for record in records:
                    if record.type == "MX":
                        results.append(f"{record.data['preference']} {record.data['exchange']}")
                    else:
                        results.append(record.data)
                    ttls.append(str(record.ttl))
                self.query_table.add_row(
                    current_time,
                    domain,
                    self._qtype_to_string(qtype),
                    client_ip,
                    source,
                    " | ".join(results),
                    " | ".join(ttls)
                )
            else:
                source = "Cache" if self._get_from_cache(cache_key) else "None"
                self.query_table.add_row(
                    current_time,
                    domain,
                    self._qtype_to_string(qtype),
                    client_ip,
                    source,
                    "Not Found",
                    "-"
                )
            self.live_display.refresh()

            response = bytearray()
            response.extend(query_id)
            if records:
                response.extend(b'\x81\x80')
                response.extend(b'\x00\x01')
                response.extend(len(records).to_bytes(2, 'big'))
                response.extend(b'\x00\x00')
                response.extend(b'\x00\x00')
                question_section = data[12:offset+4]
                response.extend(question_section)
                self.add_answer_records(response, records, question_offset)
                logging.info(f"Found {len(records)} record(s) for {domain}")
            else:
                response.extend(b'\x81\x83')
                response.extend(b'\x00\x01')
                response.extend(b'\x00\x00')
                response.extend(b'\x00\x00')
                response.extend(b'\x00\x00')
                question_section = data[12:offset+4]
                response.extend(question_section)
                logging.error(f"Domain not resolved: {domain}")
            sock.sendto(response, addr)
        except Exception as e:
            logging.error(f"Error handling query: {e}")

    def show_stats(self, query_rows=None, show_history=True):
        self.console.print("\n[bold blue]DNS Server Statistics Report[/bold blue]")
        self.console.print("=" * 50)
        uptime = datetime.now() - self.stats.start_time
        general_stats = Table(title="General Statistics", show_header=False, box=ROUNDED)
        general_stats.add_column("Metric", style="cyan", width=20)
        general_stats.add_column("Value", style="green")
        general_stats.add_row("Server Uptime", str(uptime).split('.')[0])
        general_stats.add_row("Total Queries", str(self.stats.total_queries))
        general_stats.add_row("Unique Clients", str(len(self.stats.client_ips)))
        general_stats.add_row("Cache Status", "Enabled" if self.settings.enable_cache else "Disabled")
        if self.settings.enable_cache:
            general_stats.add_row("Cache Entries", str(len(self.cache)))
        self.console.print(Panel(general_stats))
        if self.stats.host_queries:
            top_domains = sorted(self.stats.host_queries.items(), key=lambda x: x[1], reverse=True)[:10]
            domain_table = Table(title="Top 10 Queried Domains", box=ROUNDED)
            domain_table.add_column("Domain", style="cyan")
            domain_table.add_column("Queries", style="green", justify="right")
            domain_table.add_column("Percentage", style="yellow", justify="right")
            for domain, count in top_domains:
                percentage = (count / self.stats.total_queries) * 100
                domain_table.add_row(domain, str(count), f"{percentage:.1f}%")
            self.console.print(Panel(domain_table))
        if self.settings.enable_cache and self.cache:
            cache_table = Table(title="Cache Status", box=ROUNDED)
            cache_table.add_column("Domain", style="cyan")
            cache_table.add_column("Type", style="yellow")
            cache_table.add_column("TTL", style="green", justify="right")
            cache_table.add_column("Status", style="magenta")
            now = datetime.now()
            for (domain, type_), entry in self.cache.items():
                if entry.expires_at is None:
                    ttl = "∞"
                    status = "Permanent"
                else:
                    remaining = (entry.expires_at - now).total_seconds()
                    if remaining <= 0:
                        continue
                    ttl = f"{int(remaining)}s"
                    status = "Active" if not entry.records[0].not_found else "Negative"
                cache_table.add_row(domain, type_, ttl, status)
            self.console.print(Panel(cache_table))
        if show_history:
            self.console.print("\n[bold blue]Query History[/bold blue]")
            self.console.print("=" * 50)
            history_table = self._create_history_table(query_rows)
            self.console.print(history_table)
        self.console.print("\n" + "=" * 50)

    def _create_history_table(self, query_rows):
        history_table = Table(box=SIMPLE, show_header=True, header_style="bold cyan")
        history_table.add_column("Time", style="dim")
        history_table.add_column("Query", style="yellow")
        history_table.add_column("Type", style="magenta")
        history_table.add_column("Client", style="blue")
        history_table.add_column("Source", style="green")
        history_table.add_column("Result", style="cyan")
        history_table.add_column("TTL", style="dim cyan")
        if query_rows:
            for row in query_rows:
                history_table.add_row(*row)
        return history_table

    def _get_from_cache(self, cache_key: tuple) -> Optional[List[DNSRecord]]:
        if cache_key not in self.cache:
            return None
        cache_entry = self.cache[cache_key]
        if cache_entry.expires_at is None:
            return cache_entry.records
        if datetime.now() >= cache_entry.expires_at:
            del self.cache[cache_key]
            return None
        return cache_entry.records

    def _add_to_cache(self, cache_key: tuple, records: List[DNSRecord]):
        if self.settings.cache_ttl == -1:
            expires_at = None
        else:
            expires_at = datetime.now() + timedelta(seconds=self.settings.cache_ttl)
        self.cache[cache_key] = CacheEntry(records=records, expires_at=expires_at)
        logging.info(f"Added to cache: {cache_key[0]} ({cache_key[1]})")

def main():
    parser = argparse.ArgumentParser(description="Simple DNS Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=53, help="Port to bind to")
    parser.add_argument("--records", type=Path, default=Path("records.json"), help="Path to DNS records JSON file")
    parser.add_argument("--log", type=Path, help="Log file path (optional)")
    args = parser.parse_args()

    if not args.records.exists():
        default_records = {
            "settings": {
                "default_dns_servers": ["8.8.8.8", "8.8.4.4"],
                "enable_fallback": True,
                "fallback_ips": {
                    "A": "192.168.1.1",
                    "AAAA": "2001:db8::1"
                },
                "ttl": 60,
                "enable_recursive_query": True,
                "enable_cache": True,
                "cache_ttl": 600
            },
            "records": {
                "example.com": {
                    "A": ["93.184.216.34"],
                    "TTL": 300
                }
            }
        }
        args.records.write_text(json.dumps(default_records, indent=4))
        print(f"Created default {args.records} file")

    server = DNSServer(args.host, args.port, args.records, args.log)

    def handle_signal(signum, frame):
        logging.info("\nShutting down server...")
        server.show_stats()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)
    server.start()

if __name__ == "__main__":
    main()

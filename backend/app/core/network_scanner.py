"""
Network Security Scanner.

Async port scanning, DNS lookup, SSL certificate inspection,
HTTP header analysis, WHOIS lookup, ping, and traceroute.
"""

import asyncio
import logging
import platform
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import dns.resolver
import httpx

logger = logging.getLogger(__name__)

# ── Well-known port services ─────────────────────────────────────────────────

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP/Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 27017: "MongoDB",
}

# ── Security headers to check ────────────────────────────────────────────────

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "severity": "high",
        "description": "Enforces HTTPS connections",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
    },
    "content-security-policy": {
        "name": "CSP",
        "severity": "high",
        "description": "Prevents XSS and code injection",
        "recommendation": "Implement a Content-Security-Policy header",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "description": "Prevents clickjacking",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "description": "Prevents MIME type sniffing",
        "recommendation": "Add 'X-Content-Type-Options: nosniff'",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "low",
        "description": "XSS filter (legacy browsers)",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block'",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "description": "Controls referrer information",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "medium",
        "description": "Controls browser feature access",
        "recommendation": "Implement Permissions-Policy to restrict sensitive features",
    },
}


class NetworkScanner:
    """Async network security scanner."""

    # ── Port Scanning ────────────────────────────────────────────────────

    async def port_scan(
        self, target: str, ports: List[int], timeout: float = 2.0
    ) -> Dict[str, Any]:
        """
        Perform an async TCP connect scan.

        Args:
            target: IP address or hostname
            ports: List of port numbers to scan
            timeout: Connection timeout per port

        Returns:
            Scan results with open/closed/filtered ports
        """
        start = time.time()
        results = await asyncio.gather(
            *[self._check_port(target, port, timeout) for port in ports],
            return_exceptions=True,
        )

        open_ports = []
        closed = 0
        filtered = 0

        for port, result in zip(ports, results):
            if isinstance(result, Exception):
                filtered += 1
            elif result:
                service = PORT_SERVICES.get(port, "Unknown")
                open_ports.append({
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": result if isinstance(result, str) else None,
                })
            else:
                closed += 1

        duration_ms = int((time.time() - start) * 1000)

        findings = []
        for op in open_ports:
            if op["port"] in (23, 21, 135, 139, 445):
                findings.append({
                    "severity": "high",
                    "title": f"Insecure service on port {op['port']} ({op['service']})",
                    "category": "Network",
                    "description": f"{op['service']} is running on port {op['port']}. "
                                   "This service may transmit data in cleartext.",
                    "recommendation": f"Disable {op['service']} if not needed, or use a secure alternative.",
                })

        return {
            "target": target,
            "ports_scanned": len(ports),
            "open_ports": open_ports,
            "open_count": len(open_ports),
            "closed_count": closed,
            "filtered_count": filtered,
            "duration_ms": duration_ms,
            "findings": findings,
        }

    async def _check_port(
        self, host: str, port: int, timeout: float
    ) -> Optional[str]:
        """Check if a single port is open. Returns banner or True."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            # Try to grab a banner
            banner = None
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=1)
                banner = data.decode("utf-8", errors="replace").strip()
            except (asyncio.TimeoutError, Exception):
                pass
            writer.close()
            await writer.wait_closed()
            return banner or True
        except (ConnectionRefusedError, OSError):
            return None
        except asyncio.TimeoutError:
            return None

    # ── DNS Lookup ───────────────────────────────────────────────────────

    async def dns_lookup(
        self, domain: str, record_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Perform DNS lookups for specified record types."""
        record_types = record_types or ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        records = {}
        findings = []

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                records[rtype] = []
            except dns.resolver.NXDOMAIN:
                return {
                    "domain": domain,
                    "error": "Domain does not exist (NXDOMAIN)",
                    "records": {},
                    "findings": [{
                        "severity": "info",
                        "title": "Domain not found",
                        "category": "DNS",
                        "description": f"Domain '{domain}' does not exist.",
                    }],
                }
            except Exception as e:
                records[rtype] = [f"Error: {str(e)}"]

        # Check for SPF record
        txt_records = records.get("TXT", [])
        has_spf = any("v=spf1" in r for r in txt_records)
        has_dmarc = False

        try:
            dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            has_dmarc = any("v=DMARC1" in str(r) for r in dmarc_answers)
        except Exception:
            pass

        if not has_spf:
            findings.append({
                "severity": "medium",
                "title": "No SPF record found",
                "category": "DNS",
                "description": "Domain does not have an SPF record for email authentication.",
                "recommendation": "Add an SPF TXT record to prevent email spoofing.",
            })

        if not has_dmarc:
            findings.append({
                "severity": "medium",
                "title": "No DMARC record found",
                "category": "DNS",
                "description": "Domain does not have a DMARC record.",
                "recommendation": "Add a DMARC record (_dmarc.domain) for email security.",
            })

        return {
            "domain": domain,
            "records": records,
            "has_spf": has_spf,
            "has_dmarc": has_dmarc,
            "findings": findings,
        }

    # ── SSL Certificate Inspection ───────────────────────────────────────

    async def ssl_check(
        self, host: str, port: int = 443
    ) -> Dict[str, Any]:
        """Inspect SSL/TLS certificate and configuration."""
        findings = []

        try:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(socket.socket(), server_hostname=host)
            conn.settimeout(10)
            conn.connect((host, port))

            cert = conn.getpeercert()
            cipher = conn.cipher()
            version = conn.version()

            conn.close()

            # Parse certificate details
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))

            not_before = cert.get("notBefore", "")
            not_after = cert.get("notAfter", "")

            # Calculate days remaining
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_remaining = (expiry - datetime.utcnow()).days
                is_expired = days_remaining < 0
            except ValueError:
                days_remaining = -1
                is_expired = True

            # SAN (Subject Alternative Names)
            san = []
            for san_type, san_value in cert.get("subjectAltName", []):
                san.append(f"{san_type}:{san_value}")

            # Generate findings
            if is_expired:
                findings.append({
                    "severity": "critical",
                    "title": "SSL certificate is expired",
                    "category": "SSL/TLS",
                    "description": f"Certificate expired {abs(days_remaining)} days ago.",
                    "recommendation": "Renew the SSL certificate immediately.",
                })
            elif days_remaining < 30:
                findings.append({
                    "severity": "high",
                    "title": f"SSL certificate expires in {days_remaining} days",
                    "category": "SSL/TLS",
                    "description": "Certificate is expiring soon.",
                    "recommendation": "Renew the SSL certificate before expiration.",
                })

            if version and "TLSv1.0" in version:
                findings.append({
                    "severity": "high",
                    "title": "TLS 1.0 in use",
                    "category": "SSL/TLS",
                    "description": "TLS 1.0 is deprecated and has known vulnerabilities.",
                    "recommendation": "Upgrade to TLS 1.2 or TLS 1.3.",
                })

            if cipher and cipher[0]:
                cipher_name = cipher[0]
                weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]
                for wc in weak_ciphers:
                    if wc in cipher_name.upper():
                        findings.append({
                            "severity": "high",
                            "title": f"Weak cipher in use: {cipher_name}",
                            "category": "SSL/TLS",
                            "description": f"Cipher {cipher_name} contains {wc} which is considered weak.",
                            "recommendation": "Configure the server to use strong ciphers only.",
                        })

            return {
                "host": host,
                "port": port,
                "subject": subject,
                "issuer": issuer,
                "version": version,
                "serial_number": cert.get("serialNumber", ""),
                "not_before": not_before,
                "not_after": not_after,
                "days_remaining": days_remaining,
                "is_expired": is_expired,
                "signature_algorithm": None,
                "san": san,
                "protocol_version": version,
                "cipher": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else None,
                "findings": findings,
            }

        except ssl.SSLError as e:
            return {
                "host": host,
                "port": port,
                "error": f"SSL error: {str(e)}",
                "findings": [{
                    "severity": "critical",
                    "title": "SSL connection failed",
                    "category": "SSL/TLS",
                    "description": str(e),
                    "recommendation": "Check SSL/TLS configuration on the server.",
                }],
            }
        except socket.timeout:
            return {"host": host, "port": port, "error": "Connection timed out", "findings": []}
        except Exception as e:
            return {"host": host, "port": port, "error": str(e), "findings": []}

    # ── HTTP Header Analysis ─────────────────────────────────────────────

    async def check_http_headers(self, url: str) -> Dict[str, Any]:
        """Analyze HTTP response headers for security configurations."""
        findings = []

        try:
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=15, verify=False
            ) as client:
                response = await client.get(url)

            headers = dict(response.headers)
            headers_lower = {k.lower(): v for k, v in headers.items()}

            # Check each security header
            present = []
            missing = []

            for header_key, header_info in SECURITY_HEADERS.items():
                if header_key in headers_lower:
                    present.append({
                        "header": header_info["name"],
                        "value": headers_lower[header_key],
                    })
                else:
                    missing.append(header_info["name"])
                    findings.append({
                        "severity": header_info["severity"],
                        "title": f"Missing {header_info['name']} header",
                        "category": "HTTP Headers",
                        "description": header_info["description"],
                        "recommendation": header_info["recommendation"],
                    })

            # Check for information disclosure headers
            disclosure_headers = ["server", "x-powered-by", "x-aspnet-version"]
            for dh in disclosure_headers:
                if dh in headers_lower:
                    findings.append({
                        "severity": "low",
                        "title": f"Information disclosure: {dh}",
                        "category": "HTTP Headers",
                        "description": f"Header '{dh}: {headers_lower[dh]}' reveals server technology.",
                        "recommendation": f"Remove or obfuscate the '{dh}' header.",
                    })

            score = int((len(present) / len(SECURITY_HEADERS)) * 100)

            return {
                "url": url,
                "status_code": response.status_code,
                "headers": headers,
                "security_headers_present": present,
                "security_headers_missing": missing,
                "security_score": score,
                "findings": findings,
            }

        except httpx.RequestError as e:
            return {"url": url, "error": str(e), "findings": []}

    # ── WHOIS Lookup ─────────────────────────────────────────────────────

    async def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform a WHOIS lookup on a domain."""
        try:
            import whois
            w = whois.whois(domain)

            return {
                "domain": domain,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "updated_date": str(w.updated_date) if w.updated_date else None,
                "name_servers": w.name_servers if w.name_servers else [],
                "status": w.status if w.status else [],
                "registrant": w.get("org", w.get("name", None)),
                "country": w.get("country", None),
                "raw": str(w)[:2000],
            }
        except Exception as e:
            return {"domain": domain, "error": str(e)}

    # ── Ping ─────────────────────────────────────────────────────────────

    async def ping(self, target: str, count: int = 4) -> Dict[str, Any]:
        """Ping a target host."""
        param = "-n" if platform.system().lower() == "windows" else "-c"

        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", param, str(count), target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode("utf-8", errors="replace")

            # Parse stats
            packet_loss = None
            avg_latency = None

            loss_match = re.search(r"(\d+)% (?:packet )?loss", output)
            if loss_match:
                packet_loss = int(loss_match.group(1))

            # Windows: Average = Xms / Linux: avg = X
            avg_match = re.search(r"(?:Average|avg)[^=]*=\s*([\d.]+)", output, re.IGNORECASE)
            if avg_match:
                avg_latency = float(avg_match.group(1))

            return {
                "target": target,
                "reachable": proc.returncode == 0,
                "packet_loss_percent": packet_loss,
                "avg_latency_ms": avg_latency,
                "output": output,
            }
        except asyncio.TimeoutError:
            return {"target": target, "reachable": False, "error": "Ping timed out"}
        except Exception as e:
            return {"target": target, "reachable": False, "error": str(e)}

    # ── Traceroute ───────────────────────────────────────────────────────

    async def traceroute(self, target: str, max_hops: int = 30) -> Dict[str, Any]:
        """Run traceroute to a target."""
        cmd = "tracert" if platform.system().lower() == "windows" else "traceroute"
        hop_flag = "-h" if platform.system().lower() == "windows" else "-m"

        try:
            proc = await asyncio.create_subprocess_exec(
                cmd, hop_flag, str(max_hops), target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode("utf-8", errors="replace")

            # Parse hops
            hops = []
            for line in output.splitlines():
                hop_match = re.match(r"\s*(\d+)\s+(.+)", line)
                if hop_match:
                    hops.append({
                        "hop": int(hop_match.group(1)),
                        "detail": hop_match.group(2).strip(),
                    })

            return {
                "target": target,
                "max_hops": max_hops,
                "hops": hops,
                "total_hops": len(hops),
                "output": output,
            }
        except asyncio.TimeoutError:
            return {"target": target, "error": "Traceroute timed out"}
        except Exception as e:
            return {"target": target, "error": str(e)}


# Singleton
network_scanner = NetworkScanner()

import re
import random
import string
import argparse
import sys
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime


class LogRedactor:
    """
    A class to redact sensitive information from log data including:
    - IP addresses (IPv4 and IPv6)
    - Hostnames (including simple hostnames in JSON fields)
    - GUIDs/UUIDs
    - Email addresses
    - MAC addresses
    - Data-host fields
    - Connection ID fields

    Each unique item gets a consistent random identifier for tracking.
    """

    def __init__(self, seed: int = None):
        """
        Initialize the LogRedactor.

        Args:
            seed: Optional seed for reproducible random number generation
        """
        if seed is not None:
            random.seed(seed)

        # Dictionaries to track unique items and their redacted identifiers
        self.ip_mapping: Dict[str, str] = {}
        self.hostname_mapping: Dict[str, str] = {}
        self.guid_mapping: Dict[str, str] = {}
        self.email_mapping: Dict[str, str] = {}
        self.mac_mapping: Dict[str, str] = {}
        self.data_host_mapping: Dict[str, str] = {}
        self.connection_id_mapping: Dict[str, str] = {}

    def _generate_random_id(self) -> str:
        """Generate a random 6-digit identifier."""
        return ''.join(random.choices(string.digits, k=6))

    def _get_or_create_redacted_id(self, value: str, mapping: Dict[str, str],
                                    prefix: str) -> str:
        """
        Get existing redacted ID or create a new one for the given value.

        Args:
            value: The original value to redact
            mapping: The mapping dictionary for this type of data
            prefix: The prefix to use (e.g., 'IP', 'HOST', 'GUID')

        Returns:
            The redacted string with unique identifier
        """
        value_lower = value.lower()

        if value_lower not in mapping:
            random_id = self._generate_random_id()
            mapping[value_lower] = f"[REDACTED-{prefix}-{random_id}]"

        return mapping[value_lower]

    def _redact_connection_id(self, text: str) -> str:
        """
        Redact connectionId fields which contain embedded sensitive data.

        Format: connection_<IP>_<PORT>_<FQDN>_<HOSTNAME>_<PLATFORM>_<GUID>_<GUID>
        Example: connection_192.168.0.215_8089_sniffles.localdomain_sniffles_linux-aarch64_B522CEA3-..._B522CEA3-...
        """
        # Pattern to match connectionId in JSON
        connection_id_pattern = r'("connectionId"\s*:\s*")([^"]+)(")'

        def replace_connection_id(match):
            prefix = match.group(1)
            value = match.group(2)
            suffix = match.group(3)
            redacted = self._get_or_create_redacted_id(
                value, self.connection_id_mapping, 'CONNID'
            )
            return f"{prefix}{redacted}{suffix}"

        result = re.sub(connection_id_pattern, replace_connection_id, text, flags=re.IGNORECASE)

        # Also match non-JSON formats
        # connectionId=value or connectionId: value
        connection_id_pattern2 = r'(connectionId\s*[=:]\s*)([^\s,;\]\}"\']+)'

        def replace_connection_id2(match):
            prefix = match.group(1)
            value = match.group(2)
            redacted = self._get_or_create_redacted_id(
                value, self.connection_id_mapping, 'CONNID'
            )
            return f"{prefix}{redacted}"

        result = re.sub(connection_id_pattern2, replace_connection_id2, result, flags=re.IGNORECASE)

        return result

    def _redact_json_hostname_fields(self, text: str) -> str:
        """
        Redact hostname values in JSON fields.

        Handles fields like:
        - "hostname": "value"
        - "hostName": "value"
        - "host_name": "value"
        - "host": "value"
        - "server": "value"
        - "serverName": "value"
        - "machineName": "value"
        - "nodeName": "value"
        - "instanceName": "value" (if not already redacted)
        """
        # Pattern for various hostname-related JSON fields
        hostname_field_patterns = [
            r'("hostname"\s*:\s*")([^"]+)(")',
            r'("hostName"\s*:\s*")([^"]+)(")',
            r'("host_name"\s*:\s*")([^"]+)(")',
            r'("host"\s*:\s*")([^"]+)(")',
            r'("server"\s*:\s*")([^"]+)(")',
            r'("serverName"\s*:\s*")([^"]+)(")',
            r'("server_name"\s*:\s*")([^"]+)(")',
            r'("machineName"\s*:\s*")([^"]+)(")',
            r'("machine_name"\s*:\s*")([^"]+)(")',
            r'("nodeName"\s*:\s*")([^"]+)(")',
            r'("node_name"\s*:\s*")([^"]+)(")',
            r'("node"\s*:\s*")([^"]+)(")',
            r'("computerName"\s*:\s*")([^"]+)(")',
            r'("computer_name"\s*:\s*")([^"]+)(")',
            r'("deviceName"\s*:\s*")([^"]+)(")',
            r'("device_name"\s*:\s*")([^"]+)(")',
            r'("workerName"\s*:\s*")([^"]+)(")',
            r'("worker_name"\s*:\s*")([^"]+)(")',
        ]

        result = text

        for pattern in hostname_field_patterns:
            def replace_hostname_field(match):
                prefix = match.group(1)
                value = match.group(2)
                suffix = match.group(3)

                # Skip if already redacted
                if value.startswith('[REDACTED'):
                    return match.group(0)

                # Skip common non-hostname values
                skip_values = {'localhost', 'null', 'none', 'unknown', 'n/a', ''}
                if value.lower() in skip_values:
                    return match.group(0)

                redacted = self._get_or_create_redacted_id(
                    value, self.hostname_mapping, 'HOST'
                )
                return f"{prefix}{redacted}{suffix}"

            result = re.sub(pattern, replace_hostname_field, result, flags=re.IGNORECASE)

        return result

    def _redact_data_host(self, text: str) -> str:
        """
        Redact data-host field values in various formats.
        """
        patterns = [
            r'(data[-_]?host\s*[=:]\s*)["\']?([^"\'\s,;\]\}]+)["\']?',
            r'(["\']data[-_]?host["\']\s*:\s*)["\']([^"\']+)["\']',
            r'((?:data|Data)Host\s*[=:]\s*)["\']?([^"\'\s,;\]\}]+)["\']?',
            r'(data[-_]?host\s+)([^\s,;\]\}]+)',
            r'(<data[-_]?host>)([^<]+)(</data[-_]?host>)',
        ]

        result = text

        for pattern in patterns[:-1]:
            def replace_data_host(match):
                prefix = match.group(1)
                value = match.group(2)
                redacted = self._get_or_create_redacted_id(
                    value, self.data_host_mapping, 'DATAHOST'
                )
                return f"{prefix}{redacted}"

            result = re.sub(pattern, replace_data_host, result, flags=re.IGNORECASE)

        xml_pattern = patterns[-1]
        def replace_xml_data_host(match):
            open_tag = match.group(1)
            value = match.group(2)
            close_tag = match.group(3)
            redacted = self._get_or_create_redacted_id(
                value, self.data_host_mapping, 'DATAHOST'
            )
            return f"{open_tag}{redacted}{close_tag}"

        result = re.sub(xml_pattern, replace_xml_data_host, result, flags=re.IGNORECASE)

        return result

    def _redact_emails(self, text: str) -> str:
        """Redact email addresses."""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

        def replace_email(match):
            email = match.group(0)
            return self._get_or_create_redacted_id(email, self.email_mapping, 'EMAIL')

        return re.sub(email_pattern, replace_email, text)

    def _redact_mac_addresses(self, text: str) -> str:
        """Redact MAC addresses in various formats."""
        mac_patterns = [
            r'\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b',
            r'\b(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}\b',
            r'\b(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}\b',
        ]

        def replace_mac(match):
            mac = match.group(0)
            return self._get_or_create_redacted_id(mac, self.mac_mapping, 'MAC')

        result = text
        for pattern in mac_patterns:
            result = re.sub(pattern, replace_mac, result, flags=re.IGNORECASE)

        return result

    def _redact_ipv4(self, text: str) -> str:
        """Redact IPv4 addresses, including those embedded in strings."""
        # Standard IPv4 pattern - works even when embedded in other strings
        ipv4_pattern = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'

        def replace_ip(match):
            ip = match.group(0)
            return self._get_or_create_redacted_id(ip, self.ip_mapping, 'IP')

        return re.sub(ipv4_pattern, replace_ip, text)

    def _redact_ipv6(self, text: str) -> str:
        """Redact IPv6 addresses."""
        ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|\b::(?:[fF]{4}:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

        def replace_ip(match):
            ip = match.group(0)
            return self._get_or_create_redacted_id(ip, self.ip_mapping, 'IP')

        return re.sub(ipv6_pattern, replace_ip, text, flags=re.IGNORECASE)

    def _redact_guids(self, text: str) -> str:
        """Redact GUIDs/UUIDs."""
        guid_pattern = r'[{]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[}]?'

        def replace_guid(match):
            guid = match.group(0)
            return self._get_or_create_redacted_id(guid, self.guid_mapping, 'GUID')

        return re.sub(guid_pattern, replace_guid, text, flags=re.IGNORECASE)

    def _redact_hostnames(self, text: str) -> str:
        """Redact hostnames (FQDNs and common hostname patterns)."""
        hostname_pattern = r'\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})\b'

        common_tlds = {'com', 'net', 'org', 'edu', 'gov', 'io', 'co', 'local',
                       'internal', 'corp', 'lan', 'home', 'localdomain', 'dev',
                       'test', 'example', 'invalid', 'localhost', 'domain'}

        def replace_hostname(match):
            hostname = match.group(0)
            parts = hostname.lower().split('.')
            if parts[-1] in common_tlds or len(parts) >= 2:
                return self._get_or_create_redacted_id(hostname, self.hostname_mapping, 'HOST')
            return hostname

        return re.sub(hostname_pattern, replace_hostname, text, flags=re.IGNORECASE)

    def redact_line(self, line: str) -> str:
        """
        Redact all sensitive information from a single line.

        Args:
            line: A single line of log text

        Returns:
            The redacted line
        """
        # Order matters - process most specific patterns first

        # 1. Redact connectionId first (contains embedded IPs, hostnames, GUIDs)
        result = self._redact_connection_id(line)

        # 2. Redact JSON hostname fields (catches simple hostnames like "sniffles")
        result = self._redact_json_hostname_fields(result)

        # 3. Redact data-host fields
        result = self._redact_data_host(result)

        # 4. Redact emails
        result = self._redact_emails(result)

        # 5. Redact GUIDs
        result = self._redact_guids(result)

        # 6. Redact MAC addresses
        result = self._redact_mac_addresses(result)

        # 7. Redact IP addresses (including embedded ones)
        result = self._redact_ipv4(result)
        result = self._redact_ipv6(result)

        # 8. Redact FQDN hostnames
        result = self._redact_hostnames(result)

        return result

    def redact(self, text: str) -> str:
        """
        Redact all sensitive information from the given text.

        Args:
            text: The log text to redact

        Returns:
            The redacted text
        """
        lines = text.split('\n')
        redacted_lines = [self.redact_line(line) for line in lines]
        return '\n'.join(redacted_lines)

    def redact_file(self, input_path: str, output_path: str,
                    include_header: bool = True,
                    include_mapping_report: bool = False) -> Dict[str, int]:
        """
        Redact a log file and write the result to a new file.
        Processes line by line to maintain order and handle large files.

        Args:
            input_path: Path to the input log file
            output_path: Path to the output redacted file
            include_header: Whether to include a header with metadata
            include_mapping_report: Whether to append the mapping report at the end

        Returns:
            Dictionary with statistics about the redaction
        """
        input_file = Path(input_path)
        output_file = Path(output_path)

        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        line_count = 0

        with open(input_file, 'r', encoding='utf-8') as infile, \
             open(output_file, 'w', encoding='utf-8') as outfile:

            if include_header:
                header = self._generate_file_header(input_path, output_path)
                outfile.write(header)
                outfile.write("\n")

            for line in infile:
                redacted_line = self.redact_line(line)
                outfile.write(redacted_line)
                line_count += 1

            if include_mapping_report:
                outfile.write("\n\n")
                outfile.write(self.get_mapping_report())

        stats = self.get_statistics()
        stats['lines_processed'] = line_count

        return stats

    def redact_file_streaming(self, input_path: str, output_path: str,
                               buffer_size: int = 8192) -> Dict[str, int]:
        """
        Redact a large log file using streaming to minimize memory usage.

        Args:
            input_path: Path to the input log file
            output_path: Path to the output redacted file
            buffer_size: Size of the read buffer

        Returns:
            Dictionary with statistics about the redaction
        """
        input_file = Path(input_path)
        output_file = Path(output_path)

        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        line_count = 0

        with open(input_file, 'r', encoding='utf-8', buffering=buffer_size) as infile, \
             open(output_file, 'w', encoding='utf-8', buffering=buffer_size) as outfile:

            for line in infile:
                redacted_line = self.redact_line(line)
                outfile.write(redacted_line)
                line_count += 1

        stats = self.get_statistics()
        stats['lines_processed'] = line_count

        return stats

    def _generate_file_header(self, input_path: str, output_path: str) -> str:
        """Generate a header for the output file."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header_lines = [
            "#" + "=" * 78,
            "# REDACTED LOG FILE",
            "#" + "=" * 78,
            f"# Generated:     {timestamp}",
            f"# Source file:   {input_path}",
            f"# Output file:   {output_path}",
            "#",
            "# Redacted items: IP addresses, hostnames, GUIDs, emails, MAC addresses,",
            "#                 data-host fields, connection IDs, JSON hostname fields",
            "# Each unique item is assigned a consistent random identifier.",
            "#" + "=" * 78,
            ""
        ]
        return "\n".join(header_lines)

    def get_statistics(self) -> Dict[str, int]:
        """
        Get statistics about redacted items.

        Returns:
            Dictionary with counts of each redacted item type
        """
        return {
            'ip_addresses': len(self.ip_mapping),
            'hostnames': len(self.hostname_mapping),
            'guids': len(self.guid_mapping),
            'emails': len(self.email_mapping),
            'mac_addresses': len(self.mac_mapping),
            'data_hosts': len(self.data_host_mapping),
            'connection_ids': len(self.connection_id_mapping),
            'total': (len(self.ip_mapping) + len(self.hostname_mapping) +
                     len(self.guid_mapping) + len(self.email_mapping) +
                     len(self.mac_mapping) + len(self.data_host_mapping) +
                     len(self.connection_id_mapping))
        }

    def get_mapping_report(self) -> str:
        """
        Generate a report of all redacted items and their mappings.

        Returns:
            A formatted string containing all mappings
        """
        stats = self.get_statistics()

        report_lines = [
            "=" * 78,
            "REDACTION MAPPING REPORT",
            "=" * 78,
            "",
            "SUMMARY:",
            "-" * 40,
            f"  IP addresses redacted:    {stats['ip_addresses']}",
            f"  Hostnames redacted:       {stats['hostnames']}",
            f"  GUIDs redacted:           {stats['guids']}",
            f"  Email addresses redacted: {stats['emails']}",
            f"  MAC addresses redacted:   {stats['mac_addresses']}",
            f"  Data-host fields redacted:{stats['data_hosts']}",
            f"  Connection IDs redacted:  {stats['connection_ids']}",
            "-" * 40,
            f"  TOTAL UNIQUE ITEMS:       {stats['total']}",
            "",
        ]

        if self.ip_mapping:
            report_lines.append("-" * 78)
            report_lines.append("IP ADDRESS MAPPINGS:")
            report_lines.append("-" * 78)
            for original, redacted in sorted(self.ip_mapping.items()):
                report_lines.append(f"  {original:<45} -> {redacted}")
            report_lines.append("")

        if self.hostname_mapping:
            report_lines.append("-" * 78)
            report_lines.append("HOSTNAME MAPPINGS:")
            report_lines.append("-" * 78)
            for original, redacted in sorted(self.hostname_mapping.items()):
                report_lines.append(f"  {original:<45} -> {redacted}")
            report_lines.append("")

        if self.guid_mapping:
            report_lines.append("-" * 78)
            report_lines.append("GUID MAPPINGS:")
            report_lines.append("-" * 78)
            for original, redacted in sorted(self.guid_mapping.items()):
                report_lines.append(f"  {original:<45} -> {redacted}")
            report_lines.append("")

        if self.email_mapping:
            report_lines.append("-" * 78)
            report_lines.append("EMAIL ADDRESS MAPPINGS:")
            report_lines.append("-" * 78)
            for original, redacted in sorted(self.email_mapping.items()):
                report_lines.append(f"  {original:<45} -> {redacted}")
            report_lines.append("")

        if self.mac_mapping:
            report_lines.append("-" * 78)
            report_lines.append("MAC ADDRESS MAPPINGS:")
            report_lines.append("-" * 78)
            for original, redacted in sorted(self.mac_mapping.items()):
                report_lines.append(f"  {original:<45} -> {redacted}")
            report_lines.append("")

        if self.data_host_mapping:
            report_lines.append("-" * 78)
            report_lines.append("DATA-HOST FIELD MAPPINGS:")
            report_lines.append("-" * 78)
            for original, redacted in sorted(self.data_host_mapping.items()):
                report_lines.append(f"  {original:<45} -> {redacted}")
            report_lines.append("")

        if self.connection_id_mapping:
            report_lines.append("-" * 78)
            report_lines.append("CONNECTION ID MAPPINGS:")
            report_lines.append("-" * 78)
            for original, redacted in sorted(self.connection_id_mapping.items()):
                # Truncate long connection IDs for display
                display_original = original if len(original) <= 60 else original[:57] + "..."
                report_lines.append(f"  {display_original:<60}")
                report_lines.append(f"    -> {redacted}")
            report_lines.append("")

        report_lines.append("=" * 78)

        return "\n".join(report_lines)

    def export_mappings_to_json(self, filepath: str) -> None:
        """
        Export all mappings to a JSON file.

        Args:
            filepath: Path to the output JSON file
        """
        import json

        mappings = {
            'generated_at': datetime.now().isoformat(),
            'ip_addresses': self.ip_mapping,
            'hostnames': self.hostname_mapping,
            'guids': self.guid_mapping,
            'emails': self.email_mapping,
            'mac_addresses': self.mac_mapping,
            'data_hosts': self.data_host_mapping,
            'connection_ids': self.connection_id_mapping,
            'statistics': self.get_statistics()
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(mappings, f, indent=2)

    def export_mappings_to_csv(self, filepath: str) -> None:
        """
        Export all mappings to a CSV file.

        Args:
            filepath: Path to the output CSV file
        """
        import csv

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Type', 'Original Value', 'Redacted Value'])

            for original, redacted in self.ip_mapping.items():
                writer.writerow(['IP Address', original, redacted])

            for original, redacted in self.hostname_mapping.items():
                writer.writerow(['Hostname', original, redacted])

            for original, redacted in self.guid_mapping.items():
                writer.writerow(['GUID', original, redacted])

            for original, redacted in self.email_mapping.items():
                writer.writerow(['Email', original, redacted])

            for original, redacted in self.mac_mapping.items():
                writer.writerow(['MAC Address', original, redacted])

            for original, redacted in self.data_host_mapping.items():
                writer.writerow(['Data-Host', original, redacted])

            for original, redacted in self.connection_id_mapping.items():
                writer.writerow(['Connection ID', original, redacted])

    def clear_mappings(self) -> None:
        """Clear all stored mappings."""
        self.ip_mapping.clear()
        self.hostname_mapping.clear()
        self.guid_mapping.clear()
        self.email_mapping.clear()
        self.mac_mapping.clear()
        self.data_host_mapping.clear()
        self.connection_id_mapping.clear()


def create_sample_log_file(filepath: str) -> None:
    """Create a sample log file for testing including Splunk-style logs."""
    sample_logs = """2024-01-15 10:23:45 INFO  Connection established from 192.168.1.100 to server01.company.com
2024-01-15 10:23:46 DEBUG User session GUID: 550e8400-e29b-41d4-a716-446655440000 started
2024-01-15 10:23:47 WARN  Failed login attempt from 10.0.0.55 for user admin@internal.corp.net
2024-01-15 10:23:48 ERROR Database connection failed to db-master.datacenter.local (192.168.1.100)
2024-01-15 10:23:49 INFO  Request ID: {7C9E6679-7425-40DE-944B-E07FC1F90AE7} processed successfully
2024-01-15 10:23:50 DEBUG IPv6 connection from 2001:0db8:85a3:0000:0000:8a2e:0370:7334
2024-01-15 10:23:51 INFO  Backup server backup01.company.com responded with status OK
2024-01-15 10:23:52 WARN  Multiple requests from 192.168.1.100 detected (possible DDoS)
2024-01-15 10:24:00 INFO  Email notification sent to john.doe@example.com
2024-01-15 10:24:01 DEBUG Device MAC: 00:1A:2B:3C:4D:5E connected to network
2024-01-15 10:24:02 WARN  Unauthorized device AA-BB-CC-DD-EE-FF attempted connection
2024-01-15 10:26:00 INFO  data-host=production-server-01 received request
{"datetime":"02-01-2026 18:03:22.663 -0500","log_level":"INFO","component":"DSclient","data":{"guid":"B522CEA3-7295-4E59-B8FF-0B619FBA1847","instanceId":"B522CEA3-7295-4E59-B8FF-0B619FBA1847","ip":"192.168.0.215","dns":"sniffles.localdomain","hostname":"sniffles","mgmt":"8089","build":"e3bdab203ac8","instanceName":"sniffles.localdomain","connectionId":"connection_192.168.0.215_8089_sniffles.localdomain_sniffles_linux-aarch64_B522CEA3-7295-4E59-B8FF-0B619FBA1847_B522CEA3-7295-4E59-B8FF-0B619FBA1847","utsname":"linux-aarch64","splunkVersion":"9.4.1","package":"universal_forwarder","clientId":"B522CEA3-7295-4E59-B8FF-0B619FBA1847","name":"B522CEA3-7295-4E59-B8FF-0B619FBA1847","packageType":"deb","upgradeStatus":"none","upgradeTime":"none"}}
{"datetime":"02-01-2026 18:06:25.063 -0500","log_level":"INFO","component":"DSclient","data":{"guid":"B522CEA3-7295-4E59-B8FF-0B619FBA1847","instanceId":"B522CEA3-7295-4E59-B8FF-0B619FBA1847","ip":"192.168.0.215","dns":"sniffles.localdomain","hostname":"sniffles","mgmt":"8089","build":"e3bdab203ac8","instanceName":"sniffles.localdomain","connectionId":"connection_192.168.0.215_8089_sniffles.localdomain_sniffles_linux-aarch64_B522CEA3-7295-4E59-B8FF-0B619FBA1847_B522CEA3-7295-4E59-B8FF-0B619FBA1847","utsname":"linux-aarch64","splunkVersion":"9.4.1","package":"universal_forwarder","clientId":"B522CEA3-7295-4E59-B8FF-0B619FBA1847","name":"B522CEA3-7295-4E59-B8FF-0B619FBA1847","packageType":"deb","upgradeStatus":"none","upgradeTime":"none"}}
{"server": "webserver01", "host": "dbhost", "nodeName": "worker-node-5", "machineName": "prod-machine-01"}
"""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(sample_logs)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Redact sensitive information from log files.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.log output_redacted.log
  %(prog)s input.log output.log --mapping-report
  %(prog)s input.log output.log --json-export mappings.json
  %(prog)s input.log output.log --csv-export mappings.csv --no-header
  %(prog)s --demo
        """
    )

    parser.add_argument(
        'input_file',
        nargs='?',
        help='Path to the input log file'
    )

    parser.add_argument(
        'output_file',
        nargs='?',
        help='Path to the output redacted log file'
    )

    parser.add_argument(
        '--demo',
        action='store_true',
        help='Run demonstration with sample data'
    )

    parser.add_argument(
        '--no-header',
        action='store_true',
        help='Do not include header in output file'
    )

    parser.add_argument(
        '--mapping-report',
        action='store_true',
        help='Append mapping report to the output file'
    )

    parser.add_argument(
        '--json-export',
        metavar='FILE',
        help='Export mappings to a JSON file'
    )

    parser.add_argument(
        '--csv-export',
        metavar='FILE',
        help='Export mappings to a CSV file'
    )

    parser.add_argument(
        '--seed',
        type=int,
        help='Random seed for reproducible redaction IDs'
    )

    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress output messages'
    )

    return parser.parse_args()


def print_statistics(stats: Dict[str, int], quiet: bool = False) -> None:
    """Print redaction statistics."""
    if quiet:
        return

    print("\n" + "=" * 50)
    print("REDACTION COMPLETE")
    print("=" * 50)
    print(f"  Lines processed:      {stats.get('lines_processed', 'N/A')}")
    print(f"  IP addresses:         {stats['ip_addresses']}")
    print(f"  Hostnames:            {stats['hostnames']}")
    print(f"  GUIDs:                {stats['guids']}")
    print(f"  Email addresses:      {stats['emails']}")
    print(f"  MAC addresses:        {stats['mac_addresses']}")
    print(f"  Data-host fields:     {stats['data_hosts']}")
    print(f"  Connection IDs:       {stats['connection_ids']}")
    print("-" * 50)
    print(f"  TOTAL UNIQUE ITEMS:   {stats['total']}")
    print("=" * 50)


def run_demo() -> None:
    """Run a demonstration with sample data."""
    print("=" * 78)
    print("LOG REDACTION TOOL - DEMONSTRATION")
    print("=" * 78)

    sample_input = 'sample_input.log'
    sample_output = 'sample_output_redacted.log'

    print(f"\n[1] Creating sample log file: {sample_input}")
    create_sample_log_file(sample_input)

    print(f"\n[2] Original log content:")
    print("-" * 78)
    with open(sample_input, 'r') as f:
        original_content = f.read()
        print(original_content)

    print(f"\n[3] Redacting log file...")
    redactor = LogRedactor(seed=42)
    stats = redactor.redact_file(
        sample_input,
        sample_output,
        include_header=True,
        include_mapping_report=True
    )

    print(f"\n[4] Redacted log content ({sample_output}):")
    print("-" * 78)
    with open(sample_output, 'r') as f:
        print(f.read())

    print_statistics(stats)

    json_file = 'sample_mappings.json'
    csv_file = 'sample_mappings.csv'

    redactor.export_mappings_to_json(json_file)
    redactor.export_mappings_to_csv(csv_file)

    print(f"\n[5] Exported mappings to:")
    print(f"    - {json_file}")
    print(f"    - {csv_file}")

    print("\n" + "=" * 78)
    print("DEMONSTRATION COMPLETE")
    print("=" * 78)


def main():
    """Main entry point for the script."""
    args = parse_arguments()

    if args.demo:
        run_demo()
        return

    if not args.input_file or not args.output_file:
        print("Error: Both input_file and output_file are required.")
        print("Use --demo for a demonstration or --help for usage information.")
        sys.exit(1)

    redactor = LogRedactor(seed=args.seed)

    try:
        if not args.quiet:
            print(f"Processing: {args.input_file} -> {args.output_file}")

        stats = redactor.redact_file(
            args.input_file,
            args.output_file,
            include_header=not args.no_header,
            include_mapping_report=args.mapping_report
        )

        print_statistics(stats, args.quiet)

        if args.json_export:
            redactor.export_mappings_to_json(args.json_export)
            if not args.quiet:
                print(f"Mappings exported to: {args.json_export}")

        if args.csv_export:
            redactor.export_mappings_to_csv(args.csv_export)
            if not args.quiet:
                print(f"Mappings exported to: {args.csv_export}")

        if not args.quiet:
            print(f"\nRedacted log file saved to: {args.output_file}")

    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Log Redactor - Sensitive Information Redaction Tool
Supports: Splunk logs, etcd logs, metrics logs, and general log formats
Version: 2.9 (Added Splunk metrics.log support)
"""

import re
import random
import string
import argparse
import sys
from typing import Dict, Set, List, Any
from pathlib import Path
import ipaddress
import json


class LogRedactor:
    """
    A comprehensive log redaction tool that replaces sensitive information
    with consistent, trackable redacted identifiers.
    """
    
    # File extensions that should not be redacted when appearing as values
    EXCLUDED_FILE_EXTENSIONS: Set[str] = {
        '.conf', '.meta', '.spec', '.cfg', '.config', '.ini', '.yaml', '.yml',
        '.json', '.xml', '.properties', '.log', '.txt', '.csv', '.py', '.java',
        '.js', '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd', '.exe', '.dll',
        '.so', '.dylib', '.jar', '.war', '.ear', '.class', '.pyc', '.pyo',
        '.bundle', '.pem', '.crt', '.key', '.cert', '.csr', '.der', '.p12',
        '.pfx', '.jks', '.keystore', '.truststore', '.go'
    }
    
    # Patterns that indicate a path/module rather than a hostname
    LOGGER_PATH_INDICATORS: Set[str] = {
        'splunk.', 'com.', 'org.', 'net.', 'io.', 'apache.', 'java.', 'javax.',
        'sun.', 'logging.', 'log4j.', 'slf4j.', 'logback.'
    }
    
    # Go source file patterns (should not be redacted)
    GO_SOURCE_PATTERNS: Set[str] = {
        'embed/', 'etcdmain/', 'etcdserver/', 'raft/', 'mvcc/', 'membership/',
        'transport/', 'api/', 'pkg/', 'cmd/', 'internal/', 'server/', 'client/',
        'rafthttp/', 'txn/', 'cluster_util', 'traceutil/', 'v3rpc/'
    }
    
    # Data types and keywords that should not be redacted
    DATA_TYPES_AND_KEYWORDS: Set[str] = {
        'bool', 'boolean', 'int', 'integer', 'float', 'double', 'string', 'str',
        'true', 'false', 'null', 'none', 'undefined', 'nan', 'inf', 'infinity',
        'auto', 'default', 'enabled', 'disabled', 'yes', 'no', 'on', 'off',
        'existing', 'new', 'zap', 'info', 'debug', 'warn', 'error', 'fatal',
        'periodic', 'write-only', 'linux', 'amd64', 'arm64', 'darwin', 'windows',
        'ascend', 'descend', 'create', 'version', 'islearner',
        # Splunk metrics specific values
        'none', 'non-clustered', 'clustered', 'instance', 'per_host_agg_cpu',
        'per_host_thruput', 'per_sourcetype_thruput', 'per_index_thruput',
        'license_master', 'license_manager', 'search_head', 'indexer',
        'cluster_master', 'deployment_server', 'shc_member', 'shc_captain'
    }
    
    # JSON keys whose values should NEVER be redacted
    SKIP_JSON_KEYS: Set[str] = {
        'ts', 'timestamp', 'time', 'date', 'datetime', 'start', 'end',
        'start time', 'start_time', 'end time', 'end_time',
        'caller', 'logger', 'level', 'msg', 'message',
        'go-version', 'etcd-version', 'git-sha', 'version',
        'go-os', 'go-arch', 'os', 'arch', 'platform',
        'data-dir', 'wal-dir', 'member-dir', 'log-outputs',
        'snapshot-count', 'max-wals', 'max-snapshots',
        'heartbeat-interval', 'election-timeout', 'publish-timeout',
        'snapshot-catchup-entries', 'quota-backend-bytes',
        'max-request-bytes', 'max-concurrent-streams',
        'compact-check-time-interval', 'auto-compaction-mode',
        'auto-compaction-retention', 'auto-compaction-interval',
        'discovery-url', 'discovery-proxy', 'discovery-token',
        'discovery-dial-timeout', 'discovery-request-timeout',
        'discovery-keepalive-time', 'discovery-keepalive-timeout',
        'discovery-cert', 'discovery-key', 'discovery-cacert',
        'discovery-user', 'discovery-endpoints',
        'downgrade-check-interval', 'corrupt-check-time-interval',
        'max-learners', 'v2-deprecation', 'max-cpu-set', 'max-cpu-available',
        'cors', 'host-whitelist', 'feature-gates', 'pre-vote',
        'member-initialized', 'force-new-cluster', 'initial-election-tick-advance',
        'initial-corrupt-check', 'discovery-insecure-transport',
        'discovery-insecure-skip-tls-verify', 'wal-dir-dedicated',
        'experimental-local-address', 'took', 'expected-duration',
        'prefix', 'sort_order', 'sort_target', 'added-peer-is-learner',
        'duration', 'time spent', 'steps', 'step_count'
    }
    
    # JSON keys that contain hostnames
    HOSTNAME_JSON_KEYS: Set[str] = {
        'hostname', 'host', 'nodename', 'node_name', 'server', 'servername',
        'server_name', 'machine', 'machinename', 'machine_name', 'peer',
        'data-host', 'host_src', 'host_dest', 'src_host', 'dest_host',
        'source_host', 'destination_host', 'label', 'name', 'member-name',
        'local-member-name', 'peer-name'
    }
    
    # JSON keys that contain cluster specifications
    CLUSTER_SPEC_JSON_KEYS: Set[str] = {
        'initial-cluster', 'endpoints', 'members', 'cluster'
    }
    
    # JSON keys that contain URLs
    URL_JSON_KEYS: Set[str] = {
        'initial-advertise-peer-urls', 'listen-peer-urls',
        'advertise-client-urls', 'listen-client-urls',
        'listen-metrics-urls', 'peer-urls', 'client-urls', 'endpoints',
        'remote-peer-urls', 'added-peer-peer-urls', 'peer-url',
        'client-url', 'advertise-url', 'address', 'url', 'urls',
        'target', 'endpoint'
    }
    
    # JSON keys that contain free-form text/structs
    FREEFORM_TEXT_KEYS: Set[str] = {
        'error', 'request', 'response', 'key', 'value', 'range_end',
        'description', 'detail', 'details', 'reason', 'cause',
        'local-member-attributes', 'member', 'request content',
        'request_content', 'attributes'
    }
    
    # Key=value patterns in plain text logs that contain hostnames
    # These are field names where the value should be treated as a hostname
    HOSTNAME_KV_KEYS: Set[str] = {
        'server_name', 'servername', 'host', 'hostname', 'node', 'nodename',
        'node_name', 'peer', 'machine', 'machinename', 'machine_name',
        'data-host', 'data_host', 'host_src', 'host_dest', 'src_host',
        'dest_host', 'source_host', 'destination_host', 'label',
        'series', 'name', 'server', 'target_host', 'remote_host',
        'local_host', 'peer_host', 'cluster_label', 'member_name'
    }
    
    # Key=value patterns to skip (their values should not be redacted)
    SKIP_KV_KEYS: Set[str] = {
        'group', 'instance_roles', 'index_cluster_label', 'index_cluster_status',
        'license_status', 'instance_guid', 'cpu_time_ms', 'avg_cpu_time_per_event_ms',
        'bytes', 'event_count', 'kb', 'ev', 'eps', 'kbps', 'status', 'type',
        'sourcetype', 'source', 'index', 'splunk_server', 'linecount', 'level',
        'component', 'log_level', 'thread', 'class', 'method', 'file', 'line'
    }
    
    # CLI argument flags that contain hostnames
    HOSTNAME_CLI_FLAGS: Set[str] = {
        '--name', '--initial-cluster', '--initial-advertise-peer-urls',
        '--advertise-client-urls', '--listen-peer-urls', '--listen-client-urls',
        '--peer-urls', '--client-urls', '--endpoints'
    }
    
    # Flags to skip
    SKIP_CLI_FLAGS: Set[str] = {
        '--data-dir', '--log-outputs', '--logger', '--log-level',
        '--tls-min-version', '--tls-max-version', '--peer-auto-tls', '--auto-tls',
        '--initial-cluster-state', '--initial-cluster-token'
    }

    def __init__(self, seed: int = None):
        """Initialize the redactor with optional seed for reproducible IDs."""
        if seed is not None:
            random.seed(seed)
        
        self.ip_mapping: Dict[str, str] = {}
        self.hostname_mapping: Dict[str, str] = {}
        self.guid_mapping: Dict[str, str] = {}
        self.email_mapping: Dict[str, str] = {}
        self.mac_mapping: Dict[str, str] = {}
        
        self.stats = {
            'ips': 0,
            'hostnames': 0,
            'guids': 0,
            'emails': 0,
            'macs': 0,
            'lines_processed': 0
        }

    def _generate_random_id(self) -> str:
        """Generate a random 6-digit identifier."""
        return ''.join(random.choices(string.digits, k=6))

    def _get_or_create_redacted_id(
        self, 
        value: str, 
        mapping: Dict[str, str], 
        prefix: str
    ) -> str:
        """Get existing or create new redacted ID for a value."""
        value_lower = value.lower()
        if value_lower not in mapping:
            random_id = self._generate_random_id()
            mapping[value_lower] = f"[REDACTED-{prefix}-{random_id}]"
            
            stat_key = {
                'HOST': 'hostnames', 'IP': 'ips', 'GUID': 'guids',
                'EMAIL': 'emails', 'MAC': 'macs'
            }.get(prefix)
            if stat_key:
                self.stats[stat_key] += 1
                
        return mapping[value_lower]

    # =========================================================================
    # VALIDATION AND EXCLUSION METHODS
    # =========================================================================

    def _is_excluded_filename(self, value: str) -> bool:
        """Check if value appears to be a configuration filename."""
        value_lower = value.lower()
        return any(value_lower.endswith(ext) for ext in self.EXCLUDED_FILE_EXTENSIONS)

    def _is_go_source_reference(self, value: str) -> bool:
        """Check if value is a Go source file reference."""
        if re.match(r'^[a-zA-Z0-9_/]+\.go(:\d+)?$', value):
            return True
        return any(value.startswith(prefix) for prefix in self.GO_SOURCE_PATTERNS)

    def _is_logger_or_module_path(self, value: str) -> bool:
        """Check if value appears to be a logger/module path."""
        value_lower = value.lower()
        
        if any(indicator in value_lower for indicator in self.LOGGER_PATH_INDICATORS):
            return True
        
        if self._is_go_source_reference(value):
            return True
        
        return False

    def _is_data_type_or_keyword(self, value: str) -> bool:
        """Check if value is a data type or common keyword."""
        return value.lower() in self.DATA_TYPES_AND_KEYWORDS

    def _is_version_string(self, value: str) -> bool:
        """Check if value appears to be a version string."""
        if re.match(r'^v?\d+\.\d+(\.\d+)*(-[a-zA-Z0-9]+)?$', value):
            return True
        if re.match(r'^go\d+\.\d+(\.\d+)?$', value):
            return True
        return False

    def _is_timestamp_component(self, value: str) -> bool:
        """Check if value appears to be part of a timestamp."""
        if re.match(r'^\d{2}\.\d+$', value):
            return True
        if re.match(r'^\d{1,2}:\d{2}(:\d{2})?(\.\d+)?$', value):
            return True
        if re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', value):
            return True
        return False

    def _is_reserved_ip(self, ip_str: str) -> bool:
        """Check if IP is loopback or reserved."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_loopback or ip.is_reserved or ip.is_unspecified
        except ValueError:
            return False

    def _is_hex_id(self, value: str) -> bool:
        """Check if value is a hex identifier."""
        return bool(re.match(r'^[0-9a-fA-F]{16}$', value))

    def _is_trace_id(self, value: str) -> bool:
        """Check if value is a trace ID."""
        return bool(re.match(r'^trace\[\d+\]', value))

    def _is_numeric_value(self, value: str) -> bool:
        """Check if value is purely numeric (possibly with decimal)."""
        return bool(re.match(r'^-?\d+(\.\d+)?$', value))

    def _is_valid_hostname(self, value: str) -> bool:
        """Validate if a string could be a valid hostname."""
        if not value or len(value) > 253:
            return False
        
        # Must not be purely numeric
        if self._is_numeric_value(value):
            return False
        
        if value.replace('.', '').replace('-', '').replace('_', '').isdigit():
            return False
        
        # Must start with alphanumeric
        if not value[0].isalnum():
            return False
        
        # Must not be a hex ID or trace ID
        if self._is_hex_id(value) or self._is_trace_id(value):
            return False
        
        # Must not be a keyword
        if self._is_data_type_or_keyword(value):
            return False
        
        # FQDN pattern (dots)
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)+$', value):
            return True
        
        # Cloud hostname with underscores
        if re.match(r'^[a-zA-Z0-9]+([_-][a-zA-Z0-9-]+)+$', value):
            return True
        
        # Simple short hostname (letters + optional digits, like sh2, web01)
        if re.match(r'^[a-zA-Z]+[a-zA-Z0-9-]*\d*$', value) and len(value) >= 2:
            return True
        
        return False

    def _should_skip_value(self, value: str, context_key: str = None) -> bool:
        """Determine if a value should be skipped from redaction."""
        if not value or not value.strip():
            return True
        
        if value.startswith('[REDACTED'):
            return True
        
        if context_key and context_key.lower() in self.SKIP_JSON_KEYS:
            return True
        
        if self._is_excluded_filename(value):
            return True
        if self._is_data_type_or_keyword(value):
            return True
        if self._is_version_string(value):
            return True
        if self._is_timestamp_component(value):
            return True
        if self._is_go_source_reference(value):
            return True
        if self._is_hex_id(value):
            return True
        if self._is_numeric_value(value):
            return True
        
        return False

    def _redact_hostname(self, hostname: str, context_key: str = None) -> str:
        """Redact a single hostname value."""
        if self._should_skip_value(hostname, context_key):
            return hostname
        if not self._is_valid_hostname(hostname):
            return hostname
        return self._get_or_create_redacted_id(hostname, self.hostname_mapping, 'HOST')

    # =========================================================================
    # URL AND CLUSTER SPEC REDACTION
    # =========================================================================

    def _redact_url(self, url: str) -> str:
        """Redact hostname/IP within a URL."""
        if not url or not isinstance(url, str):
            return url
        
        url_pattern = r'(https?://)([^:/\s\]\[",\\]+)(:\d+)?([^\s\]\[",\\]*)?'
        
        def replace_url(match):
            protocol = match.group(1)
            host = match.group(2)
            port = match.group(3) or ''
            path = match.group(4) or ''
            
            if self._is_reserved_ip(host):
                return match.group(0)
            
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                redacted_host = self._get_or_create_redacted_id(host, self.ip_mapping, 'IP')
            else:
                redacted_host = self._redact_hostname(host)
            
            return f"{protocol}{redacted_host}{port}{path}"
        
        return re.sub(url_pattern, replace_url, url)

    def _redact_cluster_spec(self, spec: str) -> str:
        """Redact hostnames in cluster specifications."""
        if not spec or not isinstance(spec, str):
            return spec
        
        entries = spec.split(',')
        redacted_entries = []
        
        for entry in entries:
            entry = entry.strip()
            if '=' in entry and '://' in entry:
                eq_pos = entry.index('=')
                hostname_part = entry[:eq_pos]
                url_part = entry[eq_pos + 1:]
                
                redacted_hostname = self._redact_hostname(hostname_part)
                redacted_url = self._redact_url(url_part) if url_part else ''
                
                redacted_entries.append(f"{redacted_hostname}={redacted_url}")
            elif '://' in entry:
                redacted_entries.append(self._redact_url(entry))
            else:
                redacted_entries.append(entry)
        
        return ','.join(redacted_entries)

    # =========================================================================
    # STRUCT/ATTRIBUTE STRING REDACTION
    # =========================================================================

    def _redact_struct_string(self, text: str) -> str:
        """Redact hostnames in Go-style struct strings."""
        if not text or not isinstance(text, str):
            return text
        
        result = text
        
        # 1. Redact Name:hostname pattern
        result = re.sub(
            r'(Name:)([^\s,}\]\[]+)',
            lambda m: f"{m.group(1)}{self._redact_hostname(m.group(2))}" 
                      if not m.group(2).startswith('http') else m.group(0),
            result
        )
        
        # 2. Redact URLs in ClientURLs:[...] and PeerURLs:[...]
        result = re.sub(
            r'((?:Client|Peer)URLs:\[)([^\]]+)(\])',
            lambda m: f"{m.group(1)}{self._redact_url(m.group(2))}{m.group(3)}",
            result
        )
        
        # 3. Redact range_begin:/path/hostname and range_end:/path/hostname
        result = re.sub(
            r'(range_(?:begin|end):)(/[^/]+/)([^;}\s]+)',
            lambda m: f"{m.group(1)}{m.group(2)}{self._redact_hostname(m.group(3))}",
            result
        )
        
        # 4. Redact key:"/path/hostname" patterns
        result = re.sub(
            r'(key:\s*\\?")(/[^/]+/)([^"\\]+)(\\?")',
            lambda m: f'{m.group(1)}{m.group(2)}{self._redact_hostname(m.group(3))}{m.group(4)}',
            result
        )
        
        # 5. Redact range_end:"/path/hostname" patterns  
        result = re.sub(
            r'(range_end:\s*\\?")(/[^/]+/)([^"\\]+)(\\?")',
            lambda m: f'{m.group(1)}{m.group(2)}{self._redact_hostname(m.group(3))}{m.group(4)}',
            result
        )
        
        # 6. Redact any remaining URLs
        result = self._redact_url(result)
        
        # 7. Redact IPs in "dial tcp IP:port" patterns
        result = re.sub(
            r'(dial\s+tcp\s+)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?',
            lambda m: f"{m.group(1)}{self._get_or_create_redacted_id(m.group(2), self.ip_mapping, 'IP')}{m.group(3) or ''}"
                      if not self._is_reserved_ip(m.group(2)) else m.group(0),
            result
        )
        
        return result

    def _redact_freeform_text(self, text: str) -> str:
        """Redact hostnames and IPs in free-form text fields."""
        if not text or not isinstance(text, str):
            return text
        
        return self._redact_struct_string(text)

    # =========================================================================
    # SPLUNK METRICS LOG REDACTION
    # =========================================================================

    def _redact_splunk_metrics_line(self, line: str) -> str:
        """
        Redact hostnames in Splunk metrics.log format.
        Format: key=value, key="value", key=value
        """
        result = line
        
        # Build pattern for hostname keys
        hostname_keys_pattern = '|'.join(re.escape(k) for k in self.HOSTNAME_KV_KEYS)
        
        # Pattern 1: key=value (unquoted, followed by comma, space, or end)
        # Matches: server_name=sh2, series=sh2
        pattern_unquoted = rf'\b({hostname_keys_pattern})=([^,\s"]+)'
        
        def replace_unquoted(match):
            key = match.group(1)
            value = match.group(2)
            
            # Skip if value is a keyword or not a valid hostname
            if self._should_skip_value(value, key):
                return match.group(0)
            if not self._is_valid_hostname(value):
                return match.group(0)
            
            redacted = self._get_or_create_redacted_id(value, self.hostname_mapping, 'HOST')
            return f'{key}={redacted}'
        
        result = re.sub(pattern_unquoted, replace_unquoted, result, flags=re.IGNORECASE)
        
        # Pattern 2: key="value" (quoted)
        # Matches: server_name="sh2", series="sh2"
        pattern_quoted = rf'\b({hostname_keys_pattern})="([^"]+)"'
        
        def replace_quoted(match):
            key = match.group(1)
            value = match.group(2)
            
            if self._should_skip_value(value, key):
                return match.group(0)
            if not self._is_valid_hostname(value):
                return match.group(0)
            
            redacted = self._get_or_create_redacted_id(value, self.hostname_mapping, 'HOST')
            return f'{key}="{redacted}"'
        
        result = re.sub(pattern_quoted, replace_quoted, result, flags=re.IGNORECASE)
        
        return result

    def _is_splunk_metrics_line(self, line: str) -> bool:
        """Check if line is a Splunk metrics.log format."""
        # Typical pattern: timestamp INFO Metrics - group=xxx, name=xxx
        return bool(re.search(r'\b(INFO|WARN|ERROR)\s+Metrics\s+-\s+group=', line))

    # =========================================================================
    # JSON-AWARE REDACTION METHODS
    # =========================================================================

    def _redact_json_object(self, obj: Any, parent_key: str = None) -> Any:
        """Recursively redact sensitive values in a JSON object."""
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                result[key] = self._redact_json_value(key, value)
            return result
        elif isinstance(obj, list):
            return [self._redact_json_object(item, parent_key) for item in obj]
        else:
            return obj

    def _redact_json_value(self, key: str, value: Any) -> Any:
        """Redact a JSON value based on its key."""
        key_lower = key.lower()
        
        if key_lower in self.SKIP_JSON_KEYS:
            return value
        
        if isinstance(value, dict):
            return self._redact_json_object(value, key)
        
        elif isinstance(value, list):
            if key_lower in self.URL_JSON_KEYS or key_lower.endswith('-urls') or key_lower.endswith('urls'):
                return [self._redact_url(item) if isinstance(item, str) else item 
                        for item in value]
            else:
                return [self._redact_json_object(item, key) for item in value]
        
        elif isinstance(value, str):
            if key_lower in self.CLUSTER_SPEC_JSON_KEYS:
                if '=' in value and '://' in value:
                    return self._redact_cluster_spec(value)
            
            if key_lower in self.HOSTNAME_JSON_KEYS:
                return self._redact_hostname(value, key)
            
            if key_lower in self.URL_JSON_KEYS or key_lower.endswith('-urls') or key_lower.endswith('-url'):
                return self._redact_url(value)
            
            if key_lower in self.FREEFORM_TEXT_KEYS:
                return self._redact_freeform_text(value)
            
            if '://' in value:
                return self._redact_url(value)
            
            if value.startswith('{') and ('Name:' in value or 'range_' in value or 'ClientURLs:' in value):
                return self._redact_struct_string(value)
            
            if re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', value):
                return self._get_or_create_redacted_id(value, self.guid_mapping, 'GUID')
            
            if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
                return self._get_or_create_redacted_id(value, self.email_mapping, 'EMAIL')
            
            return value
        
        else:
            return value

    def _redact_etcd_args_array(self, args_list: List) -> List:
        """Redact hostnames within etcd args arrays."""
        redacted_args = []
        i = 0
        
        while i < len(args_list):
            arg = args_list[i]
            
            if not isinstance(arg, str):
                redacted_args.append(arg)
                i += 1
                continue
            
            if arg in self.HOSTNAME_CLI_FLAGS:
                redacted_args.append(arg)
                if i + 1 < len(args_list):
                    i += 1
                    next_val = args_list[i]
                    if isinstance(next_val, str):
                        if '=' in next_val and '://' in next_val:
                            redacted_args.append(self._redact_cluster_spec(next_val))
                        elif '://' in next_val:
                            redacted_args.append(self._redact_url(next_val))
                        else:
                            redacted_args.append(self._redact_hostname(next_val))
                    else:
                        redacted_args.append(next_val)
            elif arg in self.SKIP_CLI_FLAGS:
                redacted_args.append(arg)
                if i + 1 < len(args_list):
                    i += 1
                    redacted_args.append(args_list[i])
            else:
                if '://' in arg:
                    redacted_args.append(self._redact_url(arg))
                else:
                    redacted_args.append(arg)
            
            i += 1
        
        return redacted_args

    # =========================================================================
    # STANDARD REGEX-BASED REDACTION
    # =========================================================================

    def _redact_ips(self, text: str) -> str:
        """Redact IPv4 addresses."""
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        
        def replace_ip(match):
            ip = match.group(1)
            try:
                parts = [int(p) for p in ip.split('.')]
                if not all(0 <= p <= 255 for p in parts):
                    return ip
            except ValueError:
                return ip
            
            if self._is_reserved_ip(ip):
                return ip
            
            return self._get_or_create_redacted_id(ip, self.ip_mapping, 'IP')
        
        return re.sub(ip_pattern, replace_ip, text)

    def _redact_guids(self, text: str) -> str:
        """Redact GUIDs/UUIDs."""
        guid_pattern = r'\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b'
        
        def replace_guid(match):
            return self._get_or_create_redacted_id(match.group(1), self.guid_mapping, 'GUID')
        
        return re.sub(guid_pattern, replace_guid, text)

    def _redact_emails(self, text: str) -> str:
        """Redact email addresses."""
        email_pattern = r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'
        
        def replace_email(match):
            return self._get_or_create_redacted_id(match.group(1), self.email_mapping, 'EMAIL')
        
        return re.sub(email_pattern, replace_email, text)

    def _redact_macs(self, text: str) -> str:
        """Redact MAC addresses."""
        mac_pattern = r'\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b'
        
        def replace_mac(match):
            return self._get_or_create_redacted_id(match.group(1), self.mac_mapping, 'MAC')
        
        return re.sub(mac_pattern, replace_mac, text)

    def _redact_splunk_connection_ids(self, text: str) -> str:
        """Redact Splunk connectionId fields containing IPs."""
        conn_pattern = r'(connectionId["\s:=]+)connection_(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})_'
        
        def replace_conn(match):
            prefix = match.group(1)
            ip = match.group(2)
            
            if self._is_reserved_ip(ip):
                return match.group(0)
            
            redacted_ip = self._get_or_create_redacted_id(ip, self.ip_mapping, 'IP')
            return f'{prefix}connection_{redacted_ip}_'
        
        return re.sub(conn_pattern, replace_conn, text)

    # =========================================================================
    # MAIN REDACTION PIPELINE
    # =========================================================================

    def redact_line(self, line: str) -> str:
        """Apply all redaction rules to a single line."""
        if not line.strip():
            return line
        
        self.stats['lines_processed'] += 1
        stripped = line.strip()
        
        # Check for Splunk metrics.log format first
        if self._is_splunk_metrics_line(stripped):
            result = self._redact_splunk_metrics_line(line)
            result = self._redact_guids(result)
            result = self._redact_emails(result)
            result = self._redact_macs(result)
            result = self._redact_ips(result)
            return result
        
        # Try JSON-aware redaction
        if stripped.startswith('{') and stripped.endswith('}'):
            try:
                data = json.loads(stripped)
                redacted_data = self._redact_json_object(data)
                
                if 'args' in redacted_data and isinstance(redacted_data['args'], list):
                    redacted_data['args'] = self._redact_etcd_args_array(redacted_data['args'])
                
                line_ending = line[len(stripped):] if len(line) > len(stripped) else ''
                return json.dumps(redacted_data, separators=(',', ':')) + line_ending
                
            except json.JSONDecodeError:
                pass
        
        # Regex-based fallback for other formats
        result = line
        result = self._redact_splunk_metrics_line(result)  # Try metrics redaction anyway
        result = self._redact_splunk_connection_ids(result)
        result = self._redact_guids(result)
        result = self._redact_emails(result)
        result = self._redact_macs(result)
        result = self._redact_ips(result)
        
        return result

    def redact_file(
        self, 
        input_path: str, 
        output_path: str = None,
        encoding: str = 'utf-8'
    ) -> str:
        """Redact an entire file."""
        input_file = Path(input_path)
        
        if output_path is None:
            output_path = input_file.parent / f"{input_file.stem}_redacted{input_file.suffix}"
        
        output_file = Path(output_path)
        
        with open(input_file, 'r', encoding=encoding, errors='replace') as infile, \
             open(output_file, 'w', encoding=encoding) as outfile:
            
            for line in infile:
                redacted_line = self.redact_line(line)
                outfile.write(redacted_line)
        
        return str(output_file)

    def export_mappings(self, output_path: str) -> None:
        """Export redaction mappings to a file."""
        mappings = {
            'ip_mapping': {v: k for k, v in self.ip_mapping.items()},
            'hostname_mapping': {v: k for k, v in self.hostname_mapping.items()},
            'guid_mapping': {v: k for k, v in self.guid_mapping.items()},
            'email_mapping': {v: k for k, v in self.email_mapping.items()},
            'mac_mapping': {v: k for k, v in self.mac_mapping.items()},
            'statistics': self.stats
        }
        
        with open(output_path, 'w') as f:
            json.dump(mappings, f, indent=2)

    def print_stats(self) -> None:
        """Print redaction statistics."""
        print("\n" + "=" * 50)
        print("REDACTION STATISTICS")
        print("=" * 50)
        print(f"Lines processed:    {self.stats['lines_processed']:,}")
        print(f"IPs redacted:       {self.stats['ips']:,}")
        print(f"Hostnames redacted: {self.stats['hostnames']:,}")
        print(f"GUIDs redacted:     {self.stats['guids']:,}")
        print(f"Emails redacted:    {self.stats['emails']:,}")
        print(f"MACs redacted:      {self.stats['macs']:,}")
        print(f"\nUnique values:")
        print(f"  IPs:       {len(self.ip_mapping)}")
        print(f"  Hostnames: {len(self.hostname_mapping)}")
        print(f"  GUIDs:     {len(self.guid_mapping)}")
        print(f"  Emails:    {len(self.email_mapping)}")
        print(f"  MACs:      {len(self.mac_mapping)}")
        print("=" * 50)


def main():
    """Main entry point for CLI usage."""
    parser = argparse.ArgumentParser(
        description='Redact sensitive information from log files.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s input.log
  %(prog)s input.log -o redacted.log
  %(prog)s input.log --export-mappings mappings.json
  %(prog)s input.log --seed 42
        """
    )
    
    parser.add_argument('input', help='Input log file path')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--export-mappings', help='Export mappings to file')
    parser.add_argument('--seed', type=int, help='Random seed for reproducible IDs')
    parser.add_argument('--quiet', action='store_true', help='Suppress statistics output')
    
    args = parser.parse_args()
    
    if not Path(args.input).exists():
        print(f"Error: Input file '{args.input}' not found.", file=sys.stderr)
        sys.exit(1)
    
    redactor = LogRedactor(seed=args.seed)
    
    print(f"Processing: {args.input}")
    output_path = redactor.redact_file(args.input, args.output)
    print(f"Output: {output_path}")
    
    if args.export_mappings:
        redactor.export_mappings(args.export_mappings)
        print(f"Mappings exported to: {args.export_mappings}")
    
    if not args.quiet:
        redactor.print_stats()


if __name__ == '__main__':
    main()

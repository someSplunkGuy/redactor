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
    - Hostnames (including simple hostnames in JSON fields and log messages)
    - GUIDs/UUIDs
    - Email addresses
    - MAC addresses
    - Data-host fields
    - Connection ID fields
    - Server name declarations in logs
    - Key=value hostname patterns (node=, host=, server=, label=, etc.)
    - System info patterns
    
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
        """
        value_lower = value.lower()
        
        if value_lower not in mapping:
            random_id = self._generate_random_id()
            mapping[value_lower] = f"[REDACTED-{prefix}-{random_id}]"
        
        return mapping[value_lower]
    
    def _redact_system_info(self, text: str) -> str:
        """
        Redact system info patterns that contain hostnames.
        
        Handles patterns like:
        - System info: Linux, hostname, 6.8.0-1033-aws, ...
        - uname: Linux hostname 5.4.0 ...
        """
        # Pattern for "System info: OS, hostname, kernel, ..."
        system_info_pattern = r'(System\s+info:\s*\w+,\s*)([^,\s]+)(,)'
        
        def replace_system_info(match):
            prefix = match.group(1)
            hostname = match.group(2)
            suffix = match.group(3)
            
            # Skip if already redacted
            if hostname.startswith('[REDACTED'):
                return match.group(0)
            
            # Skip if it looks like a kernel version or number
            if re.match(r'^[\d\.\-]+', hostname):
                return match.group(0)
            
            redacted = self._get_or_create_redacted_id(
                hostname, self.hostname_mapping, 'HOST'
            )
            return f"{prefix}{redacted}{suffix}"
        
        result = re.sub(system_info_pattern, replace_system_info, text, flags=re.IGNORECASE)
        
        # Pattern for uname output: "Linux hostname kernel..."
        uname_pattern = r'(uname:\s*Linux\s+)([^\s]+)(\s+[\d\.])'
        
        def replace_uname(match):
            prefix = match.group(1)
            hostname = match.group(2)
            suffix = match.group(3)
            
            if hostname.startswith('[REDACTED'):
                return match.group(0)
            
            redacted = self._get_or_create_redacted_id(
                hostname, self.hostname_mapping, 'HOST'
            )
            return f"{prefix}{redacted}{suffix}"
        
        result = re.sub(uname_pattern, replace_uname, result, flags=re.IGNORECASE)
        
        return result
    
    def _redact_node_references(self, text: str) -> str:
        """
        Redact node/member references in log messages.
        
        Handles patterns like:
        - Node hostname is already part of
        - Node hostname joined
        - member hostname
        - peer hostname
        - captain hostname
        """
        patterns = [
            # "Node hostname is/has/joined/etc"
            (r'(Node\s+)([^\s]+)(\s+(?:is|has|joined|left|added|removed|elected|became|was))', 1, 2, 3),
            # "member hostname"
            (r'(member\s+)([^\s,;\]\}"\']+)', 1, 2, None),
            # "peer hostname" (when not followed by =)
            (r'(peer\s+)(?!=)([^\s,;\]\}"\']+)', 1, 2, None),
            # "captain hostname"
            (r'(captain\s+)(?!=)([^\s,;\]\}"\']+)', 1, 2, None),
        ]
        
        result = text
        
        skip_values = {
            'localhost', 'null', 'none', 'unknown', 'n/a', '', 'undefined',
            'true', 'false', 'yes', 'no', 'ok', 'error', 'success',
            'is', 'has', 'was', 'been', 'the', 'and', 'for', 'to', 'from',
            'id', 'uri', 'url', 'status', 'info', 'data', 'with',
        }
        
        for pattern_tuple in patterns:
            if len(pattern_tuple) == 4:
                pattern, g1, g2, g3 = pattern_tuple
                
                def make_replacer(grp1, grp2, grp3):
                    def replace_func(match):
                        prefix = match.group(grp1)
                        hostname = match.group(grp2)
                        suffix = match.group(grp3) if grp3 else ''
                        
                        if hostname.startswith('[REDACTED'):
                            return match.group(0)
                        
                        if hostname.lower() in skip_values:
                            return match.group(0)
                        
                        if hostname.isdigit():
                            return match.group(0)
                        
                        redacted = self._get_or_create_redacted_id(
                            hostname, self.hostname_mapping, 'HOST'
                        )
                        return f"{prefix}{redacted}{suffix}"
                    return replace_func
                
                result = re.sub(pattern, make_replacer(g1, g2, g3), result, flags=re.IGNORECASE)
            else:
                pattern, g1, g2, _ = pattern_tuple
                
                def make_replacer2(grp1, grp2):
                    def replace_func(match):
                        prefix = match.group(grp1)
                        hostname = match.group(grp2)
                        
                        if hostname.startswith('[REDACTED'):
                            return match.group(0)
                        
                        if hostname.lower() in skip_values:
                            return match.group(0)
                        
                        if hostname.isdigit():
                            return match.group(0)
                        
                        redacted = self._get_or_create_redacted_id(
                            hostname, self.hostname_mapping, 'HOST'
                        )
                        return f"{prefix}{redacted}"
                    return replace_func
                
                result = re.sub(pattern, make_replacer2(g1, g2), result, flags=re.IGNORECASE)
        
        return result
    
    def _redact_key_value_hostnames(self, text: str) -> str:
        """
        Redact hostname values in key=value patterns.
        """
        # Keys that typically contain hostnames (order matters - longer keys first)
        hostname_keys = [
            # Splunk-specific compound keys
            'REMOTE_SERVER_NAME', 'LOCAL_SERVER_NAME', 'SERVER_NAME',
            'SPLUNK_SERVER_NAME', 'CLUSTER_MASTER', 'SEARCH_HEAD',
            'DEPLOYER', 'LICENSE_MASTER', 'INDEXER_CLUSTER_MASTER',
            # Compound keys with underscores (longer patterns first)
            'host_dest', 'host_src', 'host_source', 'host_target', 'host_origin',
            'src_host', 'dst_host', 'dest_host', 'source_host', 'target_host',
            'remote_host', 'local_host', 'orig_host', 'hostname_orig',
            'splunk_server', 'search_head', 'server_name', 'host_name',
            'node_name', 'machine_name', 'computer_name',
            # Compound keys without underscores
            'srchost', 'dsthost', 'desthost', 'sourcehost', 'targethost',
            'remotehost', 'orighost', 'localhost_name', 'peerId',
            # CamelCase variants
            'hostDest', 'hostSrc', 'hostSource', 'hostTarget',
            'srcHost', 'dstHost', 'destHost', 'sourceHost', 'targetHost',
            'remoteHost', 'localHost', 'origHost', 'serverName', 'hostName',
            'nodeName', 'machineName', 'computerName', 'peerName',
            # Simple keys
            'node', 'host', 'server', 'hostname', 'machine', 'computer',
            'src', 'dst', 'dest', 'source', 'target', 'origin', 'destination',
            'client', 'peer', 'remote', 'worker', 'instance', 'label',
            'primary', 'secondary', 'master', 'slave', 'replica',
            'indexer', 'forwarder', 'captain', 'member',
            'servername', 'nodename', 'machinename', 'computername',
        ]
        
        # Build pattern to match any of these keys
        keys_pattern = '|'.join(re.escape(key) for key in hostname_keys)
        
        # Pattern: key=value (with optional quotes)
        pattern = rf'\b({keys_pattern})\s*=\s*(["\']?)([^"\'\s,;\]\}}\)\[]+)\2'
        
        # Skip values that shouldn't be redacted
        skip_values = {
            'localhost', 'null', 'none', 'unknown', 'n/a', 'undefined',
            'true', 'false', 'yes', 'no', 'ok', 'error', 'success',
            'failed', 'failure', 'complete', 'completed', 'pending',
            'enabled', 'disabled', 'active', 'inactive', 'on', 'off',
            '0', '1', '-', '*', 'any', 'all', 'local', 'default',
            'up', 'down', 'self',
        }
        
        def replace_kv_hostname(match):
            key = match.group(1)
            quote = match.group(2)
            value = match.group(3)
            
            # Handle empty values
            if not value or value.strip() == '':
                return match.group(0)
            
            # Skip if already redacted
            if value.startswith('[REDACTED'):
                return match.group(0)
            
            # Skip common non-hostname values
            if value.lower() in skip_values:
                return match.group(0)
            
            # Skip if it looks like a number, port, or path
            if value.isdigit():
                return match.group(0)
            if value.startswith('/'):
                return match.group(0)
            
            redacted = self._get_or_create_redacted_id(
                value, self.hostname_mapping, 'HOST'
            )
            return f"{key}={quote}{redacted}{quote}"
        
        return re.sub(pattern, replace_kv_hostname, text, flags=re.IGNORECASE)
    
    def _redact_server_name_declarations(self, text: str) -> str:
        """
        Redact server/host name declarations in log messages.
        """
        patterns = [
            # "My server name is" patterns
            (r'((?:My\s+)?server\s+name\s+is\s+)["\']([^"\']+)["\']', 2),
            (r'((?:My\s+)?server\s+name\s+is\s+)([^\s,;\]\}"\'\.]+)', 2),
            
            # "My host name is" patterns  
            (r'((?:My\s+)?host\s*name\s+is\s+)["\']([^"\']+)["\']', 2),
            (r'((?:My\s+)?host\s*name\s+is\s+)([^\s,;\]\}"\'\.]+)', 2),
            
            # "hostname is" patterns
            (r'(hostname\s+is\s+)["\']([^"\']+)["\']', 2),
            (r'(hostname\s+is\s+)([^\s,;\]\}"\'\.]+)', 2),
            
            # "Server:" or "Host:" patterns
            (r'((?:Server|Host)\s*:\s*)["\']([^"\']+)["\']', 2),
            (r'((?:Server|Host)\s*:\s*)([^\s,;\]\}"\']+)', 2),
            
            # "Connected to server" patterns
            (r'((?:Connected|Connecting)\s+to\s+(?:server|host)\s+)["\']([^"\']+)["\']', 2),
            (r'((?:Connected|Connecting)\s+to\s+(?:server|host)\s+)([^\s,;\]\}"\']+)', 2),
            
            # "Running on host" patterns
            (r'(Running\s+on\s+(?:server|host)\s+)["\']([^"\']+)["\']', 2),
            (r'(Running\s+on\s+(?:server|host)\s+)([^\s,;\]\}"\']+)', 2),
            
            # "from server/host" patterns
            (r'(from\s+(?:server|host)\s+)["\']([^"\']+)["\']', 2),
            (r'(from\s+(?:server|host)\s+)([^\s,;\]\}"\']+)', 2),
            
            # "to server/host" patterns
            (r'(to\s+(?:server|host)\s+)["\']([^"\']+)["\']', 2),
            (r'(to\s+(?:server|host)\s+)([^\s,;\]\}"\']+)', 2),
            
            # "on server/host" patterns
            (r'(on\s+(?:server|host)\s+)["\']([^"\']+)["\']', 2),
            (r'(on\s+(?:server|host)\s+)([^\s,;\]\}"\']+)', 2),
            
            # "node name is" patterns
            (r'((?:My\s+)?node\s*name\s+is\s+)["\']([^"\']+)["\']', 2),
            (r'((?:My\s+)?node\s*name\s+is\s+)([^\s,;\]\}"\'\.]+)', 2),
            
            # "machine name is" patterns
            (r'((?:My\s+)?machine\s*name\s+is\s+)["\']([^"\']+)["\']', 2),
            (r'((?:My\s+)?machine\s*name\s+is\s+)([^\s,;\]\}"\'\.]+)', 2),
            
            # "for splunk node" patterns (Splunk-specific)
            (r'(for\s+splunk\s+node\s*[=:]?\s*)["\']?([^\s,;\]\}"\']+)["\']?', 2),
            
            # "splunk node" patterns
            (r'(splunk\s+node\s*[=:]?\s*)["\']?([^\s,;\]\}"\']+)["\']?', 2),
            
            # "Forwarding to" patterns (Splunk-specific)
            (r'(Forwarding\s+to\s+)["\']?([^\s,;\]\}"\']+)["\']?', 2),
            
            # "Using REMOTE_SERVER_NAME=" pattern
            (r'(Using\s+\w+\s*=\s*)([^\s,;\]\}"\']+)', 2),
        ]
        
        result = text
        
        # Skip values that shouldn't be redacted
        skip_values = {'localhost', 'null', 'none', 'unknown', 'n/a', '', 
                       'true', 'false', 'yes', 'no', 'ok', 'error', 'success',
                       'failed', 'failure', 'complete', 'completed', 'pending',
                       'with', 'has', 'been', 'the', 'and', 'for', 'inside'}
        
        for pattern, value_group in patterns:
            def make_replacer(val_group):
                def replace_func(match):
                    prefix = match.group(1)
                    value = match.group(val_group)
                    
                    # Skip if already redacted
                    if value.startswith('[REDACTED'):
                        return match.group(0)
                    
                    # Skip common non-hostname values
                    if value.lower() in skip_values:
                        return match.group(0)
                    
                    # Skip if it looks like a number or port
                    if value.isdigit():
                        return match.group(0)
                    
                    redacted = self._get_or_create_redacted_id(
                        value, self.hostname_mapping, 'HOST'
                    )
                    return f"{prefix}{redacted}"
                return replace_func
            
            result = re.sub(pattern, make_replacer(value_group), result, flags=re.IGNORECASE)
        
        return result
    
    def _redact_connection_id(self, text: str) -> str:
        """
        Redact connectionId fields which contain embedded sensitive data.
        """
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
        """
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
            r'("srcHost"\s*:\s*")([^"]+)(")',
            r'("src_host"\s*:\s*")([^"]+)(")',
            r'("dstHost"\s*:\s*")([^"]+)(")',
            r'("dst_host"\s*:\s*")([^"]+)(")',
            r'("destHost"\s*:\s*")([^"]+)(")',
            r'("dest_host"\s*:\s*")([^"]+)(")',
            r'("sourceHost"\s*:\s*")([^"]+)(")',
            r'("source_host"\s*:\s*")([^"]+)(")',
            r'("targetHost"\s*:\s*")([^"]+)(")',
            r'("target_host"\s*:\s*")([^"]+)(")',
            r'("host_src"\s*:\s*")([^"]+)(")',
            r'("host_dest"\s*:\s*")([^"]+)(")',
            r'("hostSrc"\s*:\s*")([^"]+)(")',
            r'("hostDest"\s*:\s*")([^"]+)(")',
            r'("peer"\s*:\s*")([^"]+)(")',
            r'("instance"\s*:\s*")([^"]+)(")',
            r'("label"\s*:\s*")([^"]+)(")',
            r'("captain"\s*:\s*")([^"]+)(")',
            r'("member"\s*:\s*")([^"]+)(")',
            r'("master"\s*:\s*")([^"]+)(")',
            r'("slave"\s*:\s*")([^"]+)(")',
            r'("primary"\s*:\s*")([^"]+)(")',
            r'("secondary"\s*:\s*")([^"]+)(")',
        ]
        
        result = text
        
        # Skip values that shouldn't be redacted
        skip_values = {'localhost', 'null', 'none', 'unknown', 'n/a', '', 
                       'true', 'false', '0.0.0.0', '127.0.0.1', 'up', 'down',
                       'enabled', 'disabled', 'active', 'inactive'}
        
        for pattern in hostname_field_patterns:
            def replace_hostname_field(match):
                prefix = match.group(1)
                value = match.group(2)
                suffix = match.group(3)
                
                # Skip if already redacted
                if value.startswith('[REDACTED'):
                    return match.group(0)
                
                # Skip common non-hostname values
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
        """
        # Order matters - process most specific patterns first
        
        # 1. Redact connectionId first (contains embedded IPs, hostnames, GUIDs)
        result = self._redact_connection_id(line)
        
        # 2. Redact system info patterns (Linux, hostname, kernel...)
        result = self._redact_system_info(result)
        
        # 3. Redact node references (Node hostname is...)
        result = self._redact_node_references(result)
        
        # 4. Redact server name declarations (e.g., "My server name is")
        result = self._redact_server_name_declarations(result)
        
        # 5. Redact key=value hostname patterns (e.g., node=sh2, host=server01, host_src=sh2, label=sh2)
        result = self._redact_key_value_hostnames(result)
        
        # 6. Redact JSON hostname fields (catches simple hostnames like "sniffles", "label":"sh2")
        result = self._redact_json_hostname_fields(result)
        
        # 7. Redact data-host fields
        result = self._redact_data_host(result)
        
        # 8. Redact emails
        result = self._redact_emails(result)
        
        # 9. Redact GUIDs
        result = self._redact_guids(result)
        
        # 10. Redact MAC addresses
        result = self._redact_mac_addresses(result)
        
        # 11. Redact IP addresses (including embedded ones)
        result = self._redact_ipv4(result)
        result = self._redact_ipv6(result)
        
        # 12. Redact FQDN hostnames
        result = self._redact_hostnames(result)
        
        return result
    
    def redact(self, text: str) -> str:
        """
        Redact all sensitive information from the given text.
        """
        lines = text.split('\n')
        redacted_lines = [self.redact_line(line) for line in lines]
        return '\n'.join(redacted_lines)
    
    def redact_file(self, input_path: str, output_path: str, 
                    include_header: bool = True,
                    include_mapping_report: bool = False) -> Dict[str, int]:
        """
        Redact a log file and write the result to a new file.
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
        """Redact a large log file using streaming to minimize memory usage."""
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
            "#                 data-host fields, connection IDs, server name declarations,",
            "#                 key=value hostname patterns, system info, node references",
            "# Each unique item is assigned a consistent random identifier.",
            "#" + "=" * 78,
            ""
        ]
        return "\n".join(header_lines)
    
    def get_statistics(self) -> Dict[str, int]:
        """Get statistics about redacted items."""
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
        """Generate a report of all redacted items and their mappings."""
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
                display_original = original if len(original) <= 60 else original[:57] + "..."
                report_lines.append(f"  {display_original:<60}")
                report_lines.append(f"    -> {redacted}")
            report_lines.append("")
        
        report_lines.append("=" * 78)
        
        return "\n".join(report_lines)
    
    def export_mappings_to_json(self, filepath: str) -> None:
        """Export all mappings to a JSON file."""
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
        """Export all mappings to a CSV file."""
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
02-18-2026 16:34:53.513 +0000 INFO  ServerConfig [0 MainThread] - My server name is "sh2".
02-18-2026 16:34:53.514 +0000 INFO  ServerConfig [0 MainThread] - My host name is "indexer01".
02-18-2026 16:34:53.515 +0000 INFO  ServerConfig [0 MainThread] - Connected to server "master-node".
02-18-2026 16:34:53.516 +0000 INFO  ServerConfig [0 MainThread] - Running on host 'web-frontend-03'.
02-18-2026 16:34:53.517 +0000 INFO  ServerConfig [0 MainThread] - Server: api-backend-01
02-18-2026 16:34:53.518 +0000 INFO  ServerConfig [0 MainThread] - Connecting to host search-head-02
02-18-2026 16:35:08.224 +0000 INFO  WorkloadManager [5097 MainThread] - Workload management for splunk node=sh2 with guid=B522CEA3-7295-4E59-B8FF-0B619FBA1847 has been disabled.
02-18-2026 16:35:08.225 +0000 INFO  ClusterManager [5097 MainThread] - Peer node=indexer01 joined the cluster.
02-18-2026 16:35:08.226 +0000 INFO  SearchHead [5097 MainThread] - Search dispatched to peer=sh3 with host=search-node-05
02-18-2026 16:35:08.227 +0000 INFO  Forwarder [5097 MainThread] - Data received from src_host=collector01 target=indexer02
02-18-2026 16:36:28.079 +0000 WARN  TcpOutputProc [5306 indexerPipe] - The TCP output processor has paused the data flow. Forwarding to host_dest= inside output group group1 from host_src=sh2 has been blocked for blocked_seconds=50.
02-18-2026 16:36:28.080 +0000 WARN  TcpOutputProc [5306 indexerPipe] - Forwarding to host_dest=indexer03 from host_src=sh2 resumed.
02-18-2026 16:36:28.081 +0000 INFO  TcpOutputProc [5306 indexerPipe] - Connection established: host_source=forwarder01 host_target=indexer04
02-18-2026 16:46:35.688 +0000 ERROR SHCRaftConsensus [12602 TcpChannelThread] - Node sh2 is already part of cluster id=B522CEA3-7295-4E59-B8FF-0B619FBA1847. To add a new member via this node use new_member_uri.
02-18-2026 16:47:49.749 +0000 INFO  SHCMaster [12595 TcpChannelThread] - SHCluster membership generated for nascent: {"event":"add","status":{"captain":{"label":"sh2","id":"B522CEA3-7295-4E59-B8FF-0B619FBA1847"},"peers":{"B522CEA3-7295-4E59-B8FF-0B619FBA1848":{"label":"sh3","status":"Up"}}}}
02-18-2026 16:54:20.904 +0000 INFO  loader [15153 MainThread] - System info: Linux, sh2, 6.8.0-1033-aws, #35~22.04.1-Ubuntu SMP Wed Jul 23 17:51:00 UTC 2025, x86_64.
02-18-2026 16:54:20.929 +0000 INFO  LMTracker [15153 MainThread] - init'ing peerId=B522CEA3-7295-4E59-B8FF-0B619FBA1847 label=sh2 [30,30,self]
02-18-2026 16:46:12.049 +0000 INFO  ServerConfig [12619 AuditSearchExecutor] - Using REMOTE_SERVER_NAME=sh2
{"server": "webserver01", "host": "dbhost", "nodeName": "worker-node-5", "machineName": "prod-machine-01", "host_src": "source-server", "host_dest": "dest-server", "label": "my-label-host"}
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
    
    parser.add_argument('input_file', nargs='?', help='Path to the input log file')
    parser.add_argument('output_file', nargs='?', help='Path to the output redacted log file')
    parser.add_argument('--demo', action='store_true', help='Run demonstration with sample data')
    parser.add_argument('--no-header', action='store_true', help='Do not include header in output file')
    parser.add_argument('--mapping-report', action='store_true', help='Append mapping report to the output file')
    parser.add_argument('--json-export', metavar='FILE', help='Export mappings to a JSON file')
    parser.add_argument('--csv-export', metavar='FILE', help='Export mappings to a CSV file')
    parser.add_argument('--seed', type=int, help='Random seed for reproducible redaction IDs')
    parser.add_argument('--quiet', action='store_true', help='Suppress output messages')
    
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
        print(f.read())
    
    print(f"\n[3] Redacting log file...")
    redactor = LogRedactor(seed=42)
    stats = redactor.redact_file(sample_input, sample_output, include_header=True, include_mapping_report=True)
    
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

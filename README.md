▗▄▄▖ ▗▄▄▄▖▗▄▄▄  ▗▄▖  ▗▄▄▖▗▄▄▄▖▗▖  ▗▖▗▄▄▄▖
▐▌ ▐▌▐▌   ▐▌  █▐▌ ▐▌▐▌     █  ▐▛▚▞▜▌▐▌   
▐▛▀▚▖▐▛▀▀▘▐▌  █▐▛▀▜▌▐▌     █  ▐▌  ▐▌▐▛▀▀▘
▐▌ ▐▌▐▙▄▄▖▐▙▄▄▀▐▌ ▐▌▝▚▄▄▖  █  ▐▌  ▐▌▐▙▄▄▖
                                                                                  
Written by Jeremy Nenadal and Claude Opus 4.5. 
jnenadal@cisco.com

redactme.py is a script used for redacting log files. You can use this to remove data from Cisco-restricted log files within a Splunk diag for collaboration with engineers or safely posting in meeting chats. 


+-------------------------------------------------------------------+----------------------------------+---------------------------------------------------+
|                 Data-Host Field Formats Supported                 |                                  |                                                   |
+-------------------------------------------------------------------+----------------------------------+---------------------------------------------------+
| The script redacts data-host fields in the following formats: |                                  |                                                   |
| Format                                                            | Example                          | Redacted Output                                   |
| Equals sign                                                       | data-host=server-01              | data-host=[REDACTED-DATAHOST-123456]              |
| Colon                                                             | data-host: server-01             | data-host: [REDACTED-DATAHOST-123456]             |
| Double quotes                                                     | data-host="server-01"            | data-host="[REDACTED-DATAHOST-123456]"            |
| Single quotes                                                     | data-host='server-01'            | data-host='[REDACTED-DATAHOST-123456]'            |
| JSON format                                                       | {"data-host": "server-01"}       | {"data-host": "[REDACTED-DATAHOST-123456]"}       |
| Underscore variant                                                | data_host=server-01              | data_host=[REDACTED-DATAHOST-123456]              |
| camelCase                                                         | dataHost=server-01               | dataHost=[REDACTED-DATAHOST-123456]               |
| PascalCase                                                        | DataHost=server-01               | DataHost=[REDACTED-DATAHOST-123456]               |
| Space separated                                                   | data-host server-01              | data-host [REDACTED-DATAHOST-123456]              |
| XML format                                                        | <data-host>server-01</data-host> | <data-host>[REDACTED-DATAHOST-123456]</data-host> |
| Sample Output                                                     |                                  |                                                   |
+-------------------------------------------------------------------+----------------------------------+---------------------------------------------------+

Sample output:
2024-01-15 10:26:00 INFO  data-host=production-server-01 received request
2024-01-15 10:26:04 DEBUG {"data-host": "api-gateway-03", "status": "healthy"}
2024-01-15 10:26:10 WARN  data-host=production-server-01 high CPU usage detected

Redacted version:
2024-01-15 10:26:00 INFO  data-host=[REDACTED-DATAHOST-123456] received request
2024-01-15 10:26:04 DEBUG {"data-host": "[REDACTED-DATAHOST-789012]", "status": "healthy"}
2024-01-15 10:26:10 WARN  data-host=[REDACTED-DATAHOST-123456] high CPU usage detected

Note that production-server-01 gets the same redacted ID in both occurrences, maintaining consistency for tracking.


+------------------+------------------------------------+
| Features Summary |                                    |
+------------------+------------------------------------+
| Feature          | Description                        |
| IP addresses     | IPv4 and IPv6                      |
| Hostnames        | FQDNs and common patterns          |
| GUIDs/UUIDs      | Various formats                    |
| Email addresses  | Standard format                    |
| MAC addresses    | Colon, hyphen, Cisco dot notation  |
| Data-host fields | Multiple formats (see table above) |
| Consistent IDs   | Same value = same redacted ID      |
| File output      | Maintains original line order      |
| Export options   | JSON and CSV mapping exports       |
+------------------+------------------------------------+

Usage:
python redactme.py <sourceFile> <destinationFile>

Simply tell redactme what to read and where to put the results. Be sure to review your results and report any issues via email so I can add redactions for any unredacted data. 

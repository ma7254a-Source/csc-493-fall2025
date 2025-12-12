#!/usr/bin/env python3
import json
import sys
import re
from datetime import datetime

def parse_mitmproxy_log(log_file):
    events = []
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            
            # Parse HTTP methods (HEAD, GET, POST, etc.)
            if re.search(r'\b(GET|POST|PUT|DELETE|HEAD|PATCH)\b', line):
                parts = line.split()
                
                # Find the method
                method = None
                url = None
                client_info = line.split(':')[0] if ':' in line else 'unknown'
                
                for i, part in enumerate(parts):
                    if part in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'PATCH']:
                        method = part
                        if i + 1 < len(parts):
                            url = parts[i + 1]
                        break
                
                if method and url:
                    event = {
                        'timestamp': datetime.now().isoformat(),
                        'type': 'http_request',
                        'method': method,
                        'url': url,
                        'client_ip': client_info
                    }
                    
                    # Check for status code in the same or next lines
                    if '200' in line:
                        event['status_code'] = 200
                    elif '500' in line:
                        event['status_code'] = 500
                    elif '502' in line:
                        event['status_code'] = 502
                    
                    events.append(event)
            
            # Count client connections
            elif 'client connect' in line.lower():
                client_ip = line.split(':')[0] if ':' in line else 'unknown'
                events.append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'client_connect',
                    'client_ip': client_ip
                })
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return []
    
    return events

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: parse_mitm_logs.py <log_file>")
        sys.exit(1)
    
    events = parse_mitmproxy_log(sys.argv[1])
    print(json.dumps(events, indent=2))

#!/usr/bin/env python3
import json
import sys

def parse_suricata_log(log_file, attacker_ip='192.168.56.150'):
    """Parse Suricata eve.json and filter for relevant events"""
    events = []
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    
                    src_ip = event.get('src_ip', '')
                    dest_ip = event.get('dest_ip', '')
                    
                    if attacker_ip in [src_ip, dest_ip]:
                        simplified_event = {
                            'timestamp': event.get('timestamp', ''),
                            'event_type': event.get('event_type', ''),
                            'src_ip': src_ip,
                            'dest_ip': dest_ip,
                            'src_port': event.get('src_port', ''),
                            'dest_port': event.get('dest_port', ''),
                            'proto': event.get('proto', '')
                        }
                        
                        if event.get('event_type') == 'http':
                            http = event.get('http', {})
                            simplified_event['http_method'] = http.get('http_method', '')
                            simplified_event['http_url'] = http.get('url', '')
                            simplified_event['http_status'] = http.get('status', '')
                        
                        events.append(simplified_event)
                        
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"Error parsing line: {e}", file=sys.stderr)
                    continue
    
    except FileNotFoundError:
        print(f"Error: Log file not found: {log_file}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"Error reading log: {e}", file=sys.stderr)
        return []
    
    return events

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: parse_suricata_logs.py <suricata_eve.json> [attacker_ip]")
        sys.exit(1)
    
    log_file = sys.argv[1]
    attacker_ip = sys.argv[2] if len(sys.argv) > 2 else '192.168.56.150'
    
    events = parse_suricata_log(log_file, attacker_ip)
    
    print(json.dumps(events, indent=2))
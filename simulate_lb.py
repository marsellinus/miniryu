import socket
import sys
import time
import urllib.request
from urllib.error import URLError, HTTPError

def simulate_load_balancer(vip="10.0.0.100", port=80, requests=10):
    print(f"Starting Load Balancer simulation against VIP {vip}:{port}...")
    print(f"Sending {requests} HTTP GET requests.\n")
    
    url = f"http://{vip}:{port}"
    
    for i in range(requests):
        print(f"Request [{i+1}/{requests}] to {url} ... ", end="")
        try:
            # Send a simple HTTP GET request with a 2-second timeout
            # We don't care much about the content, just the connection success
            req = urllib.request.Request(url)
            start_time = time.time()
            
            with urllib.request.urlopen(req, timeout=2.0) as response:
                elapsed = time.time() - start_time
                status = response.getcode()
                # Try to read a tiny bit of the response to see which server answered
                # Usually simple python http servers send something like "Directory listing for /"
                server_response = response.read(64).decode('utf-8', errors='ignore').split('\n')[0]
                
                print(f"SUCCESS (Status: {status}, {elapsed*1000:.0f}ms)")
                print(f"    -> Response preview: {server_response.strip()[:40]}...")
                
        except HTTPError as e:
            # The server responded but with an error code (404, 500, etc)
            print(f"HTTP Error {e.code}")
        except URLError as e:
            # Connection failed entirely (timeout, connection refused, host unreachable)
            print(f"FAILED ({e.reason})")
        except socket.timeout:
            print("TIMEOUT (Server didn't respond)")
        except Exception as e:
            print(f"Error: {e}")
            
        time.sleep(1) # Wait 1 second before the next request

if __name__ == "__main__":
    vip = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.100"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    requests = int(sys.argv[3]) if len(sys.argv) > 3 else 6
    
    simulate_load_balancer(vip, port, requests)

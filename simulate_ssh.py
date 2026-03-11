import socket
import sys
import time

def simulate_ssh_bruteforce(target_ip, port=22, attempts=6):
    print(f"Starting SSH brute-force simulation against {target_ip}:{port}...")
    
    for i in range(attempts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            
            print(f"[{i+1}/{attempts}] Connecting to {target_ip}:{port}...", end=" ")
            
            s.connect((target_ip, port))
            print("Connected (Unexpected!)")
            
        except ConnectionRefusedError:
            print("Connection Refused (SYN packet was sent)")
        except socket.timeout:
            print("Timeout (SYN packet was likely blocked/dropped)")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            s.close()
            
        # Small delay between attempts
        time.sleep(0.1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 simulate_ssh.py <target_ip>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    simulate_ssh_bruteforce(target_ip)

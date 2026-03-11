# SDN Controller + Flask Dashboard Run Guide

## 1. Install Dependencies

```bash
pip install -r requirements.txt
```

If you use an old Mininet VM (for example Ubuntu 12 Quantal), `pip` may fail to download from PyPI with TLS errors.

Recommended approach for old VM:

- Run Ryu + Mininet inside VM.
- Run Flask dashboard on a modern host OS (Windows/Linux) and point it to VM Ryu API.

Example host setting:

```bash
export RYU_API_URL=http://<VM_IP>:8080/api
python3 -m web.app
```

Legacy VM fallback (best effort, no guarantee on very old repos):

```bash
sudo apt-get update
sudo apt-get install -y python-flask python-requests
```

Note: this project targets Python 3. On Ubuntu 12, Python 3 package versions are usually too old for reliable Flask dashboard runtime.

If Mininet is not installed yet (Ubuntu/Linux usually):

```bash
sudo apt-get install mininet
```

## 2. Run Ryu Controller

From project root:

```bash
ryu-manager main.py --ofp-tcp-listen-port 6633 --wsapi-port 8080
```

Ryu REST endpoints exposed by this project:

- `GET /api/status`
- `GET /api/attacks`
- `POST /api/block_ip`
- `POST /api/load_balancer/enable`
- `POST /api/load_balancer/disable`

## 3. Run Mininet Topology

Universal command (recommended first try):

```bash
sudo mn --controller=remote,ip=127.0.0.1 --topo=single,3
```

If controller does not connect on old VM, use explicit OpenFlow 1.0 + port 6633:

```bash
sudo mn --topo single,3 --controller remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow10
```

Quick verification in Mininet CLI:

```bash
sh ovs-vsctl get-controller s1
```

Expected output should include:

- `tcp:127.0.0.1:6633`

## 4. Run Flask Dashboard

In a new terminal from project root:

```bash
set RYU_API_URL=http://127.0.0.1:8080/api
set ADMIN_USERNAME=admin
set ADMIN_PASSWORD=admin
python -m web.app
```

Open dashboard at:

- `http://127.0.0.1:5000/login`

## 6. Run Simulations

Inside the mininet CLI:

1. DDoS Simulation
```bash
h2 python3 simulate_ddos.py h3
```

2. Bruteforce Simulation
```bash
h1 python3 simulate_ssh.py h3
```

3. Load Balancer Simulation
```bash
# Run two backend server
h2 python3 -m http.server 80 &
h3 python3 -m http.server 80 &

# Run the script to Virtual IP
h1 python3 simulate_lb.py 10.0.0.100 80
```

## 5. Flask Dashboard APIs

These are provided by Flask (proxying to Ryu where needed):

- `GET /network/status`
- `GET /attacks`
- `POST /block_ip`
- `POST /enable_load_balancer`
- `POST /disable_load_balancer`

## Notes

- Default load balancer VIP is `10.0.0.100`.
- Default backend server placeholders are `10.0.0.2` and `10.0.0.3` with ports `2` and `3`.
- For production, change Flask secret key and admin credentials.

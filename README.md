# SDN-Integrated Online Examination Network (Topic 18)

An application-aware Software-Defined Networking (SDN) and low-level TCP socket system designed in Mininet using OpenFlow 1.3 (`os-ken`) and Open vSwitch (OVS) Linux HTB Quality-of-Service (QoS) queues.

---

## 1. System Architecture & Rubric Mapping

### Network Topology (`topo.py`)
The network is structured as a star/bottleneck topology centered around an OpenFlow 1.3 switch (`s1`), where all links are constrained via Linux Traffic Control (`TCLink`) to **10 Mbps bandwidth** and **5 ms propagation delay**:

| Node | IPv4 Address | MAC Address | Switch Port | Role in System |
| :--- | :--- | :--- | :--- | :--- |
| **`h_server`** | `10.0.0.100/24` | `00:00:00:00:01:00` | `s1-eth1` | Concurrent TCP Online Exam Server (`Port 9999`) + `iperf3` congestion sink (`Port 5201`) |
| **`h1` – `h5`** | `10.0.0.11` – `10.0.0.15` | `00:00:00:00:00:01` – `05` | `s1-eth2` – `eth6` | 5 Concurrent Student TCP Clients taking the examination |
| **`h_rogue`** | `10.0.0.50/24` | `00:00:00:00:00:50` | `s1-eth7` | Unauthorized brute-force host testing SDN switch-edge drop rules |
| **`h_bg`** | `10.0.0.99/24` | `00:00:00:00:00:99` | `s1-eth8` | Background congestion traffic generator (`iperf3` TCP flooder) |

### Socket-SDN Control Loop & QoS Queue Architecture
Bottleneck switch port `s1-eth1` (facing `h_server`) is partitioned into two hardware/kernel Hierarchical Token Bucket (`linux-htb`) queues:
* **Queue 0 (Best-Effort / Background Traffic):** Capped at **2 Mbps max** (`min-rate=1Mbps, max-rate=2Mbps`).
* **Queue 1 (High-Priority Exam Traffic):** Guaranteed **8 Mbps min**, up to **10 Mbps** (`min-rate=8Mbps, max-rate=10Mbps`).

#### Multi-Tier OpenFlow 1.3 Priority Hierarchy (`sdn_ctrller.py`):
1. **Priority `0` (Table-Miss):** Sends unmatched packets to the controller (`OFPP_CONTROLLER`).
2. **Priority `10` (Standard L2 Forwarding + Queue `0`):** Non-exam traffic (ARP, ICMP, `iperf3` congestion on port `5201`) is mapped to `Queue 0` so background floods cannot starve the examination server.
3. **Priority `50` (TCP Port `9999` Handshake & Auth Intercept):** Forwards unauthenticated TCP Port `9999` packets through the controller (`OFPPacketOut`) until the Exam Server issues an authentication verdict. Legitimate students get **3 login attempts** (`AUTH_RETRY`) so accidental roll-number typos do not trigger a block.
4. **Priority `100` (Verified Student Offload + Queue `1`):** Upon observing `AUTH_OK` from `exam_server.py`, the controller installs bidirectional 5-tuple OpenFlow rules with `OFPActionSetQueue(1)`, offloading all subsequent question/answer packets (`GET_QUESTION`, `SUBMIT_ANS`) directly to the OVS kernel table at line rate.
5. **Priority `200` (Dynamic Brute-Force Mitigation / Switch-Edge Drop):** If a client fails all 3 login attempts, `exam_server.py` emits `SDN_BLOCK_HOST`. The controller intercepts this payload and installs a `Priority 200` rule with `actions=[]` (`DROP`) matching `ipv4_src`, blocking all future TCP `SYN` packets from the rogue IP at the switch edge.

---

## 2. TCP Wire Protocol (`protocol.py`)

Because TCP is a byte-stream protocol susceptible to packet concatenation under congestion, every application message is framed with a **4-byte unsigned big-endian length header (`!I`)** followed by a UTF-8 JSON payload:

```text
+-----------------------------------+---------------------------------------------------+
| 4-Byte Length Prefix (uint32 !I)  | UTF-8 JSON Payload (e.g., {"type": "AUTH", ...})  |
+-----------------------------------+---------------------------------------------------+
```

* **Client $\rightarrow$ Server Messages:** `AUTH`, `GET_QUESTION`, `SUBMIT_ANS`, `FINISH_EXAM`
* **Server $\rightarrow$ Client Messages:** `AUTH_OK`, `AUTH_RETRY`, `SDN_BLOCK_HOST`, `QUESTION`, `ACK_ANS`, `TIME_UP`, `RESULT`

---

## 3. Team Environment Setup (Headless Ubuntu 22.04 VM + VS Code Remote-SSH)

> **Why Not WSL2?** Microsoft's default WSL2 kernel strips out Linux Traffic Control (`sch_htb`, `sch_netem`) and Open vSwitch kernel modules required by Mininet `TCLink` QoS queues. We use a lightweight headless **Ubuntu 22.04 LTS** VM managed by Canonical Multipass (~350 MB idle RAM) connected via **VS Code Remote-SSH**.

### Step 1: Install Multipass & Launch the Headless VM (Windows PowerShell as Admin)
Run the following in an **Administrator PowerShell** window:

```powershell
# 1. Install Canonical Multipass
winget install Canonical.Multipass

# 2. Restart PowerShell as Admin, then launch Ubuntu 22.04 LTS (Do NOT use 24.04)
multipass launch 22.04 --name cn-mini-proj-vm --cpus 4 --memory 4G --disk 20G
```
*(Note: Wait until the image download reaches 100% and prints `Launched: cn-mini-proj-vm`. If a download is ever interrupted and causes a hash mismatch error, run `Stop-Service Multipass`, then `Remove-Item -Recurse -Force "C:\ProgramData\Multipass\cache\*"`, then `Start-Service Multipass`, and `multipass purge`).*

### Step 2: Configure SSH Key & VS Code `Remote - SSH` (Windows PowerShell as Admin)

```powershell
# 1. Generate an Ed25519 SSH key on Windows (if you don't already have one)
if (!(Test-Path "$HOME\.ssh\id_ed25519.pub")) { ssh-keygen -t ed25519 -N '""' -f "$HOME\.ssh\id_ed25519" }

# 2. Copy your public key into the Multipass VM
multipass transfer "$HOME\.ssh\id_ed25519.pub" cn-mini-proj-vm:/home/ubuntu/mykey.pub
multipass exec cn-mini-proj-vm -- bash -c "cat /home/ubuntu/mykey.pub >> /home/ubuntu/.ssh/authorized_keys && rm /home/ubuntu/mykey.pub"

# 3. Auto-detect the VirtualBox NAT SSH HostPort and write ~/.ssh/config
$vboxFile = Get-ChildItem -Path "C:\ProgramData\Multipass" -Filter "cn-mini-proj-vm.vbox" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
$port = ([regex]::Match((Get-Content $vboxFile -Raw), 'hostport="(\d+)" guestport="22"')).Groups[1].Value

@"
Host cn-mini-proj-vm
    HostName 127.0.0.1
    Port $port
    User ubuntu
    IdentityFile ~/.ssh/id_ed25519
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
"@ | Set-Content "$HOME\.ssh\config"

Write-Host "SSH configured on 127.0.0.1:$port! Connect via VS Code Remote-SSH to 'cn-mini-proj-vm'."
```

> **Note After Rebooting Windows:** Whenever you restart your laptop, start the VM via `multipass start cn-mini-proj-vm` in Admin PowerShell and re-run Step 3 above to refresh the dynamic port in `~/.ssh/config`.

### Step 3: Install Mininet, OVS, and Python Dependencies (Inside the Ubuntu VM)
In VS Code, press `Ctrl+Shift+P` $\rightarrow$ **Remote-SSH: Connect to Host...** $\rightarrow$ `cn-mini-proj-vm`. Open the integrated terminal (`Ctrl+\``) and run:

```bash
# 1. Install Mininet, Open vSwitch, and traffic utilities
sudo apt update
sudo apt install -y mininet openvswitch-switch openvswitch-common \
    openvswitch-testcontroller iproute2 iperf3 tcpdump tmux python3-pip python3-venv git

# Disable default testcontroller daemon so port 6633/6653 stays free for our SDN controller
sudo systemctl stop openvswitch-testcontroller || true
sudo systemctl disable openvswitch-testcontroller || true
sudo systemctl enable --now openvswitch-switch

# 2. Clone the repository and create a virtual environment with system-site-packages (for Mininet)
git clone <YOUR_GITHUB_REPO_URL> ~/sdn-exam-network
cd ~/sdn-exam-network
python3 -m venv --system-site-packages venv
source venv/bin/activate

# 3. Expose apt's dist-packages to VS Code Pylance & install OS-Ken SDN Controller
echo "/usr/lib/python3/dist-packages" > ~/sdn-exam-network/venv/lib/python3.10/site-packages/ubuntu-apt.pth
pip install --upgrade pip
pip install os-ken matplotlib pandas
```

---

## 4. Running the End-to-End Automated Demonstration

Open **two terminal tabs** in VS Code connected to `cn-mini-proj-vm`:

### Terminal 1: Start the OpenFlow 1.3 SDN Controller
```bash
cd ~/sdn-exam-network
source venv/bin/activate
python3 sdn_ctrller.py
```

### Terminal 2: Launch Mininet Topology, Congestion Test & Student Clients
```bash
cd ~/sdn-exam-network
sudo mn -c
sudo ~/sdn-exam-network/venv/bin/python3 topo.py
```

### What the Automated Demo Executes:
1. Boots switch `s1` (`OpenFlow13`) and configures `Queue 0` (2 Mbps max) and `Queue 1` (8–10 Mbps guaranteed) on `s1-eth1`.
2. Starts `exam_server.py` on `h_server` (`10.0.0.100:9999`) and saturates the link with a 10 Mbps `iperf3` TCP stream from `h_bg` (`10.0.0.99`).
3. Connects 5 concurrent students (`PES1`–`PES5` on `h1`–`h5`). `PES1` intentionally simulates a first-attempt typo (`PES1_TYPO`), receives `AUTH_RETRY`, recovers on Attempt 2, and is promoted to `Priority 100` (`Queue 1`).
4. Connects an unauthorized node (`HACKER99` on `h_rogue` / `10.0.0.50`), fails 3 login attempts, triggers `SDN_BLOCK_HOST`, and verifies that subsequent TCP `SYN` packets time out at the switch edge (`Priority 200, actions=drop`).
5. Logs per-question and per-answer RTTs to `exam_metrics.jsonl`, computes **Jain's Fairness Index**, and dumps the live OpenFlow 1.3 table (`ovs-ofctl -O OpenFlow13 dump-flows s1`).

---

## 5. Experimental Results: Baseline vs. SDN-Prioritized QoS

Under heavy 10 Mbps link saturation (`iperf3` flood from `h_bg` $\rightarrow$ `h_server` alongside 5 concurrent exam clients):

| Metric | Baseline (No SDN Priority 100 / Shared Queue 0) | Proposed System (Dynamic SDN Priority 100 + Queue 1) | Improvement |
| :--- | :--- | :--- | :--- |
| **Per-Exchange Question/ACK RTT** | `314.95 ms` – `774.49 ms` (Mean: `438.36 ms`) | **`16.55 ms` – `28.70 ms` (Mean: `22.51 ms`)** | **94.86% Lower Latency** |
| **Overall Session Mean RTT** | `505.73 ms` | **`174.03 ms`** | **65.59% Reduction** |
| **Total Exam Completion Time** | `6.79 s` – `7.67 s` | **`3.02 s` – `3.56 s`** | **2.2x Faster Completion** |
| **Jain's Fairness Index ($J$)** | `0.9968` | **`0.9839`** | **High Fairness Maintained** |
| **Unauthorized Host Mitigation** | Server CPU processes repeated sockets | **Switch drops `SYN` at edge (`n_packets=5` dropped)** | **Zero Server Load** |

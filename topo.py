# topo.py


"""
    - Builds a star/bottleneck topology around OpenFlow 1.3 switch 's1':
        1. h_server (10.0.0.100): TCP online exam server (port 9999) + iperf3 sink.
        2. h1 - h5 (10.0.0.11 - 10.0.0.15): 5 concurrent student nodes taking the exam.
        3. h_rogue (10.0.0.50): Unauth-ed brute-force host (tests SDN switch blocking)
        4. h_bg (10.0.0.99): Background congestion gen-ner (iperf3 flooder)
        All links use Linux Traffic Ctrl (TCLink) capped at 10Mbps with 5ms delay.
    - Configs Linux HTB QoS queues on switch port 's1-eth1' (the bottleneck link to h_server):
        1. Queue 0 (Best effort - Background noise): Capped at 2Mbps max.
        2. Queue 1 (High priority - Exam port 9999): Guaranteed 8Mbps min, up to 10Mbps.
    - Runs the end-to-end automated scenario:
        1. Starts exam_server.py & saturates the link with iperf3 congestion from h_bg.
        2. Runs h1 - h5 concurrently (with h1 simulating a 1st-attempt login typo that recovers).
        3. Runs h_rogue failing 3 login attempts & verifying OpenFlow switch-edge pkt drop.
        4. Computes mean RTT & Jain's Fairness Index across all 5 students & dumps OpenFlow rules.
"""


from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

import json, os, subprocess, sys, time


PYTHON_BIN = sys.executable


class ExamNetTopo(Topo):

    def build(self):
        # Create an Open vSwitch strictly for OpenFlow 1.3
        s1 = self.addSwitch('s1', cls = OVSSwitch, protocols = 'OpenFlow13')

        # Port 1 on s1 (s1-eth1): Exam server on a 10Mbps/5ms bottleneck like
        h_server = self.addHost('h_server', ip = '10.0.0.100/24', mac = '00:00:00:00:01:00')
        self.addLink(h_server, s1, cls = TCLink, bw = 10, delay = '5ms')

        # Ports 2-6 on s1: 5 concurrent student clients (10.0.0.11 to 10.0.0.15)
        for i in range(1, 6):
            h = self.addHost(f'h{i}', ip = f'10.0.0.1{i}/24', mac = f'00:00:00:00:00:0{i}')
            self.addLink(h, s1, cls = TCLink, bw = 10, delay = '5ms')

        # Port 7 on s1: Rogue/unauth-ed client
        h_rogue = self.addHost('h_rogue', ip = '10.0.0.50/24', mac = '00:00:00:00:00:50')
        self.addLink(h_rogue, s1, cls = TCLink, bw = 10, delay = '5ms')

        # Port 8 on s1: Background congestion traffic gen-ner
        h_bg = self.addHost('h_bg', ip = '10.0.0.99/24', mac = '00:00:00:00:00:99')
        self.addLink(h_bg, s1, cls = TCLink, bw = 10, delay = '5ms')


def config_ovs_qos():
    """
        Partitions switch port s1-eth1 (conn-ed to h_server) into 2 Linux HTB QoS queues:
            - Queue 0 (Best effort/background congestion): min 1Mbps, max 2Mbps
            - Queue 1 (High priority/exam traffic port 9999): min 8Mbps, max 10Mbps
        
        When sdn_ctrller.py executes OFPActionSetQueue(1) for auth-ed students & OFPActionSetQueue(0) for background traffic, Open vSwitch enforces these bandwidths.
    """

    info("Config-ing OVS OpenFlow 1.3 HTB QoS queues on bottleneck port s1-eth1\n")
    
    cmd = (
        "ovs-vsctl -- set Port s1-eth1 qos=@newqos -- --id=@newqos create QoS type=linux-htb other-config:max-rate=10000000 queues=0=@q0,1=@q1 -- --id=@q0 create Queue"
        " other-config:min-rate=1000000 other-config:max-rate=2000000 -- --id=@q1 create Queue other-config:min-rate=8000000 other-config:max-rate=10000000"
    )
    subprocess.run(cmd, shell = True, check = False, stdout = subprocess.DEVNULL)

def jains_fairness_index(vals):
    """
        Calcs Jain's Fairness Index: J = (sum(x_i))^2/(n*sum(x_i^2)). Ranges from 1/n (worst case) to 1.0 (all students experienced identical res times.)
    """

    if not vals: return 0.0

    n = len(vals)

    numerator = sum(vals)**2
    denominator = n*sum(v**2 for v in vals)

    return numerator/denominator if denominator > 0 else 0.0

def run_automated_demo():
    topo = ExamNetTopo()

    net = Mininet(
        topo = topo,
        controller = lambda name: RemoteController(name, ip = '127.0.0.1', port = 6633),
        switch = OVSSwitch,
        link = TCLink,
        autoSetMacs = False
    )
    net.start()

    config_ovs_qos()

    time.sleep(2.0)

    h_server = net.get('h_server')
    h_bg = net.get('h_bg')
    h_rogue = net.get('h_rogue')
    students = [net.get(f'h{i}') for i in range(1, 6)]

    log_path = 'exam_metrics.jsonl'

    if os.path.exists(log_path): os.remove(log_path)

    info("\n 1. Starting pure-TCP online exam server on h_server (10.0.0.100:9999)\n")
    
    srv_proc = h_server.popen([PYTHON_BIN, 'exam_server.py', '--duration', '45'])
    bg_srv = h_server.popen(['iperf3', '-s', '-p', '5201'])

    time.sleep(1.0)

    info("2. Injecting heavy background congestion (h_bg -> h_server on TCP port 5201)\n")
    bg_client = h_bg.popen(['iperf3', '-c', '10.0.0.100', '-p', '5201', '-t', '20'])
    time.sleep(1.0)

    info("3. Launching 5 concurrent students (h1 - h5) under congestion\n")
    info("(Note: h1/PES1 simulates a 1st-attempt roll no. typo to test retry recovery)\n")

    student_procs = []

    for idx, h in enumerate(students, start = 1):
        cmd = [PYTHON_BIN, 'student_client.py', '--id', f'PES{idx}', '--server', '10.0.0.100', '--think', '0.4', '--log', log_path]

        # Student 1 simulating a typo on attempt 1 & success on attempt 2.
        if idx == 1: cmd.append('--typo-first')

        p = h.popen(cmd)
        student_procs.append(p)

    info("\n4. Launching unauth-ed host (h_rogue/HACKER99) -> Tests 3-strike SDN block\n")

    rogue_proc = h_rogue.popen([PYTHON_BIN, 'student_client.py', '--id', 'HACKER99', '--server', '10.0.0.100'])
    rogue_out, _ = rogue_proc.communicate()

    print(rogue_out.decode('utf-8', errors = 'ignore').strip())

    info("\n5. Collecting exam completions from legit students (h1 - h5):\n")

    for p in student_procs:
        out, _ = p.communicate()

        print(out.decode('utf-8', errors = 'ignore').strip())

    # Compute performance & fairness metrics
    if os.path.exists(log_path):
        with open(log_path, 'r', encoding = 'utf-8') as f:
            records = [json.loads(line) for line in f if line.strip()]

            if records:
                rtts = [r['avg_rtt_ms'] for r in records]
                fairness = jains_fairness_index(rtts)

                info("PERFORMANCE EVALUATION (5 Students Under Congestion):\n")
                info(f"- Students Completed: {len(records)}/5\n")
                info(f"- Per-Student Avg RTT (ms): {rtts}\n")
                info(f"- Overall Mean RTT: {sum(rtts)/len(rtts):.2f} ms\n")
                info(f"- Jain's Fairness Index: {fairness:.4f} (1.0000 = Perfect Fairness)\n")

    info("\n7. Dumping active OpenFlow 1.3 flow table on switch s1:\n")

    subprocess.run("ovs-ofctl -O OpenFlow13 dump-flows s1", shell = True)

    bg_client.terminate()
    bg_srv.terminate()
    srv_proc.terminate()
    
    ovs_cleanup = "ovs-vsctl clear Port s1-eth1 qos -- --all destroy QoS -- --all destroy Queue"

    subprocess.run(ovs_cleanup, shell = True, check = False, stdout = subprocess.DEVNULL)

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')

    run_automated_demo()
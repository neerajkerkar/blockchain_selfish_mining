import network
import json
import socket
import sys
import random
import threading
import hashlib
import time
import struct
import datetime
import collections

def hash_bytes_to_int(bytes):
    return bytes[0] + bytes[1] * (2**8)

def ip_to_bytes(ip):
    ip_as_bytes = bytes(map(int, ip.split('.')))
    return ip_as_bytes

def bytes_to_ip(ip_as_bytes):
    return ".".join(map(str, ip_as_bytes))

def port_to_bytes(port):
    port = int(port)
    return bytes([port // 256, port % 256])

def bytes_to_port(port_as_bytes):
    return port_as_bytes[0] * 256 + port_as_bytes[1]

class Block:
    def __init__(self, creator_ip, creator_port, prev_hash, merkle_root, timestamp, hash):
        self.creator_ip = creator_ip
        self.creator_port = creator_port
        self.prev_hash = prev_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.hash = hash
        self.depth = 0

    def __str__(self):
        s = "prev_hash:" + str(hash_bytes_to_int(self.prev_hash))
        s += ", timestamp:" + datetime.datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        s += ", hash:" + str(hash_bytes_to_int(self.hash))
        s += ", creator:" + self.creator_ip + ":" + str(self.creator_port)
        return s

    def to_bytes(self):
        return ip_to_bytes(self.creator_ip) + port_to_bytes(self.creator_port) + self.prev_hash + self.merkle_root + struct.pack("d", self.timestamp)

    @classmethod
    def create_block_from_bytes(cls, block_bytes):
        ip = bytes_to_ip(block_bytes[0:4])
        port = bytes_to_port(block_bytes[4:6])
        prev_hash = block_bytes[6:8]
        merkle_root = block_bytes[8:10]
        timestamp = struct.unpack("d", block_bytes[10:])[0]
        hash = hash_block(block_bytes)
        return cls(ip, port, prev_hash, merkle_root, timestamp, hash)


class Blockchain:

    def __init__(self):
        self.blocks = {}
        genesis_block = Block("0.0.0.0", 0, b'\x00\x00', b'\x00\x00', 0.0, b'\x9e\x1c')
        self.genesis_block = genesis_block
        self.blocks[genesis_block.hash] = genesis_block
        self.max_depth = 0
        self.max_depth_block = genesis_block

    def is_block_valid(self, block):
        if block.hash in self.blocks:
            return False
        if abs(time.time() - block.timestamp) > 3600:
            return False
        return True

    def add_block(self, block):
        longest_chain_increased = False
        self.blocks[block.hash] = block
        if block.prev_hash in self.blocks:
            block.depth = self.blocks[block.prev_hash].depth + 1
            if block.depth > self.max_depth:
                self.max_depth = block.depth
                self.max_depth_block = block
                longest_chain_increased = True
        return longest_chain_increased

    def get_mining_power_utilization(self):
        return (self.max_depth+1)/len(self.blocks)

    def get_fraction_of_blocks_in_longest_chain(self, creator):
        creator_ip, creator_port = split_machine_addr(creator)
        hash = self.max_depth_block.hash
        chain_len = self.max_depth_block.depth + 1
        creator_blocks = 0
        while hash in self.blocks:
            block = self.blocks[hash]
            if block.creator_ip == creator_ip and block.creator_port == creator_port:
                creator_blocks += 1
            hash = block.prev_hash
        return creator_blocks/chain_len

    def get_avg_interarrival_in_longest_chain(self):
        interarrival_sum = 0
        hash = self.max_depth_block.prev_hash
        next_block_arrival = self.max_depth_block.timestamp
        chain_len = self.max_depth_block.depth + 1
        while hash in self.blocks:
            if hash == self.genesis_block.hash:
                break
            block = self.blocks[hash]
            this_block_arrival = block.timestamp
            interarrival_sum += (next_block_arrival - this_block_arrival)
            hash = block.prev_hash
            next_block_arrival = this_block_arrival
        return interarrival_sum/max(chain_len-1, 1)



interarrivaltime = int(sys.argv[1])
globalLambda = 1.0/interarrivaltime
nodeHashPower = float(sys.argv[3])
miner_type = sys.argv[4]
localLambda = (nodeHashPower * globalLambda) / 100.0

blockchainLock = threading.Lock()
blockchain = Blockchain()
secret_blocks = collections.deque()
selfish_miner_state = '0'
longest_chain_change_event = threading.Event()

myConnections = {}
myConnectionsLock = threading.Lock()
myHostname = sys.argv[2]
myIp = myHostname.split(":")[0]
myPort = int(myHostname.split(":")[1])
seeds = sys.argv[5].split(",")
mining_starter_machine = seeds[0]
myAddr = {"ip":myIp, "port":myPort}

random.seed(1570982055 + myPort)

attacker_mchine = "x.x.x.x:0"
if miner_type == "selfish":
    attacker_mchine = myHostname
if len(sys.argv) > 6:
    attacker_mchine = sys.argv[6]

def split_machine_addr(addr):
    ip, port = addr.split(":")
    port = int(port)
    return ip, port

def getName(ip, port):
    return ip + ":" + str(port)


def initConn(allHosts, maxConn):
    hosts_combined = {}
    for seed_machine in allHosts:
        for client_machine in allHosts[seed_machine]:
            hosts_combined[client_machine] = True
    selected_hosts = random.sample(hosts_combined.keys(), k=min(len(hosts_combined), maxConn))
    print("host selected for connection",selected_hosts)

    for host in selected_hosts:
        ip, port = split_machine_addr(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        myConnections[host] = sock
        network.send_msg(sock, json.dumps(myAddr).encode())
        threading.Thread(target=conn_thread_function[miner_type], args=(sock, host,)).start()

def get_msg_hash(msg):
    m = hashlib.sha256()
    m.update(msg)
    return m.digest()

def hash_block(block_bytes):
    m = hashlib.sha3_256()
    m.update(block_bytes)
    return m.digest()[-2:]

def forward(msg, exclude_peers=[]):
    if type(msg) == str:
        msg = msg.encode()
    myConnectionsLock.acquire()
    try:
        for host in myConnections:
            if host not in exclude_peers:
                conn = myConnections[host]
                network.send_msg(conn, msg)
    finally:
        myConnectionsLock.release()

def connThread(sock, connHost):
    while True:
        try:
            msg = network.get_msg(sock)
        except:
            print("connection broken with " + connHost)
            return
        block_bytes = msg
        block = Block.create_block_from_bytes(block_bytes)
        blockchainLock.acquire()
        if blockchain.is_block_valid(block):
            print("block received: "+ str(block))
            longest_chain_changed = blockchain.add_block(block)
            forward(msg, [connHost])
            if longest_chain_changed:
                longest_chain_change_event.set()
        blockchainLock.release()

def mine():
    print("mining started")
    while True:
        waitingTime = random.expovariate(localLambda)
        longest_chain_change_event.wait(waitingTime)
        blockchainLock.acquire()
        if not longest_chain_change_event.is_set(): #timeout
            prev_block = blockchain.max_depth_block
            new_block = Block(myIp, myPort, prev_block.hash, b'00', time.time(), None)
            block_in_bytes = new_block.to_bytes()
            new_block.hash = hash_block(block_in_bytes)
            blockchain.add_block(new_block)
            print("block generated:" + str(new_block))
            forward(block_in_bytes)
        else:
            longest_chain_change_event.clear()
        blockchainLock.release()

def selfish_connThread(sock, connHost):
    global selfish_miner_state
    #print("selfish conn thread started with ", connHost)
    while True:
        try:
            msg = network.get_msg(sock)
        except:
            print("connection broken with " + connHost)
            return
        block_bytes = msg
        block = Block.create_block_from_bytes(block_bytes)
        blockchainLock.acquire()
        if blockchain.is_block_valid(block):
            print("block received: "+ str(block))
            longest_chain_changed = blockchain.add_block(block)
            if longest_chain_changed:
                #print("longest chain changed")
                if selfish_miner_state == '0' or selfish_miner_state == '0p':
                    selfish_miner_state = '0'
                    longest_chain_change_event.set()
                else:
                    while True:
                        block_to_release = secret_blocks.popleft()
                        blockchain.add_block(block_to_release)
                        blockchain.max_depth_block = block_to_release
                        forward(block_to_release.to_bytes())
                        if len(secret_blocks) == 0 or len(secret_blocks) >= 2:
                            break
                    if selfish_miner_state == '1':
                        selfish_miner_state = '0p'
                    else:
                        selfish_miner_state = str(len(secret_blocks))
                print("selfish_miner_state:",selfish_miner_state)
        blockchainLock.release()

def selfish_miner():
    global selfish_miner_state
    print("selfish mining started")
    while True:
        waitingTime = random.expovariate(localLambda)
        longest_chain_change_event.wait(waitingTime)
        blockchainLock.acquire()
        if not longest_chain_change_event.is_set():  # timeout
            if len(secret_blocks) == 0:
                prev_block = blockchain.max_depth_block
            else:
                prev_block = secret_blocks[-1]
            new_block = Block(myIp, myPort, prev_block.hash, b'00', time.time(), None)
            block_in_bytes = new_block.to_bytes()
            new_block.hash = hash_block(block_in_bytes)
            print("block generated:" + str(new_block))
            if selfish_miner_state != '0p':
                secret_blocks.append(new_block)
                selfish_miner_state = str(int(selfish_miner_state) + 1)
            else: # state is 0p
                selfish_miner_state = '0'
                blockchain.add_block(new_block)
                forward(block_in_bytes)
            print("selfish_miner_state:", selfish_miner_state)
        else:
            longest_chain_change_event.clear()
        blockchainLock.release()




def listen():

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((myIp, myPort))
    listener.listen()
    while True:
        (clientsocket, address) = listener.accept()
        hostaddr = json.loads(network.get_msg(clientsocket))
        hostname = getName(hostaddr["ip"], hostaddr["port"])
        if str(hostaddr["port"]) == mining_starter_machine.split(":")[1]:
            threading.Thread(target=mining_function[miner_type]).start()
        else:
            myConnectionsLock.acquire()
            myConnections[hostname] = clientsocket
            threading.Thread(target=conn_thread_function[miner_type], args=(clientsocket, hostname,)).start()
            myConnectionsLock.release()


mining_function = {"honest":mine, "selfish":selfish_miner}
conn_thread_function = {"honest":connThread, "selfish":selfish_connThread}
threading.Thread(target=listen).start()

allHosts = {}
for seed_machine in seeds:
    ip, port = split_machine_addr(seed_machine)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    network.send_msg(sock, json.dumps(myAddr).encode())
    msg = network.get_msg(sock)
    host_data = json.loads(msg)
    allHosts[seed_machine] = host_data
    print("host list", host_data, "received from seed", seed_machine)

#print("allhosts",allHosts)
initConn(allHosts, 4)

while(True):
    #press enter to print blockchain stats
    inp = input()
    blockchainLock.acquire()
    if inp == 'r': #release all secret blocks
        while len(secret_blocks) > 0:
            block_to_release = secret_blocks.popleft()
            blockchain.add_block(block_to_release)
            blockchain.max_depth_block = block_to_release
            forward(block_to_release.to_bytes())
        print("all secret blocks released")
        selfish_miner_state = '0'
    print("mining power utilization", blockchain.get_mining_power_utilization())
    print("fraction of attacker (", attacker_mchine, ") blocks in longest chain", blockchain.get_fraction_of_blocks_in_longest_chain(attacker_mchine))
    print("avg interarrival time in longest chain", blockchain.get_avg_interarrival_in_longest_chain())
    blockchainLock.release()
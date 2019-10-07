import network
import json
import socket
import threading
import sys

hosts = {}
myHostname = sys.argv[1]
myIp = myHostname.split(":")[0]
myPort = int(myHostname.split(":")[1])
myAddr = {"ip":myIp, "port":myPort}

serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind((myIp, myPort))
serversocket.listen(5)


def seed():
    while True:
        (clientsocket, address) = serversocket.accept()
        msg = network.get_msg(clientsocket)
        data = json.loads(msg)
        machine = str(data["ip"]) + ":" + str(data["port"])
        print("connection request received from", machine)
        network.send_msg(clientsocket, json.dumps(hosts).encode())
        hosts[machine] = True


def start_mining_signal():
    print("start mining signal about to be sent")
    for machine in hosts:
        ip, port = machine.split(":")
        port = int(port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        network.send_msg(sock, json.dumps(myAddr).encode())


threading.Thread(target=seed).start()
arg = input() #press enter to send mining signal
start_mining_signal()
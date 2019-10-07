Examples of commands:

Seed format: python3 seed.py seedIP:seedPort
python3 seed.py 192.168.1.250:8000

Client format: python3 client.py interarivalTimeInSecs clientIP:clientPort fracHashPower minerType seedIP:seedPort attackerIP:attackerPort(optional)
python3 client.py 5 192.168.1.250:8001 20 honest 192.168.1.250:8000 192.168.1.250:8004
python3 client.py 5 192.168.1.250:8002 20 honest 192.168.1.250:8000 192.168.1.250:8004
python3 client.py 5 192.168.1.250:8003 20 honest 192.168.1.250:8000 192.168.1.250:8004
python3 client.py 5 192.168.1.250:8004 40 selfish 192.168.1.250:8000

How to run:
First start seed then clients
After all clients have been started press ENTER in seed terminal to signal miners to start mining
While mining press ENTER in any client terminal at any time to see stats of the blockchain (like mining power utilization) 

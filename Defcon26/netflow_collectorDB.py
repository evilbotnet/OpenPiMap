import socket, struct # Raw socket access
import time # Time..
from config import listening_port # uses config file to save configurable data
import sqlite3 # SQLlite database interaction
from socket import inet_ntoa # For parsing packets
import requests # Makes web requests to retrieve WAN IP address

# Retrieve WAN IP Address for later parsing
try:
    home = requests.get('http://ipquail.com/ip').text.strip("\n\r")
    print(home)
    with open("ip.txt", "w") as text_file:
        print(home, file=text_file)
except:
    file = open("ip.txt","r")
    home = file.readline()
    print('Using old IP of ' + str(home))

WAN_IP = home

conn = sqlite3.connect('netflow.db')
conn.execute("CREATE TABLE IF NOT EXISTS traffic (src text, sport int, packet int, \
    bytes int, dest text, dport int , time text)")

SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48

print("Collector started at: ", time.strftime("%H:%M:%S %d-%m-%Y"))

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', listening_port))
current_day = time.strftime("%d-%b-%Y")


while True:
    buf, addr = s.recvfrom(1500)

    (version, count) = struct.unpack('!HH',buf[0:4])
    if version != 5:
            print("Not NetFlow v5!")
            continue

    uptime = socket.ntohl(struct.unpack('I',buf[4:8])[0])
    epochseconds = socket.ntohl(struct.unpack('I',buf[8:12])[0])

    for i in range(0, count):
        try:
            base = SIZE_OF_HEADER+(i*SIZE_OF_RECORD)

            data = struct.unpack('!IIIIHH',buf[base+16:base+36])
            nfdata = {}
            nfdata['saddr'] = inet_ntoa(buf[base + 0:base + 4])
            nfdata['daddr'] = inet_ntoa(buf[base + 4:base + 8])
            nfdata['pcount'] = data[0]
            nfdata['bcount'] = data[1]
            nfdata['stime'] = data[2]
            nfdata['etime'] = data[3]
            nfdata['sport'] = data[4]
            nfdata['dport'] = data[5]
            nfdata['protocol'] = inet_ntoa(buf[base + 39])
        except:
            continue
    #print(nfdata)


    current_day = time.strftime("%H:%M:%S %d-%m-%Y")
    #print(current_day)
    sourceIP = nfdata['saddr']
    destIP = nfdata['daddr']

    if sourceIP == WAN_IP:
        sourceIP = 'HOME'
    else:
        destIP = 'HOME'
    print("%s:%s %s bytes -> %s:%s" % (sourceIP, nfdata['sport'],
                                           nfdata['bcount'], destIP,
                                           nfdata['dport']))

    conn.execute("INSERT INTO traffic VALUES (?, ?, ?, ?, ?, ?, ?)", (sourceIP, nfdata['sport'],
                nfdata['pcount'], nfdata['bcount'],
                destIP, nfdata['dport'],
                current_day))
    conn.commit()

    #print("db write..")
    #print("Wrote data to netflowData-" + current_day + ".csv at " + time.strftime("%H:%M:%S %d-%m-%Y"))
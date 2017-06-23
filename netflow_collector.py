import socket, struct
import csv
import time

from socket import inet_ntoa

SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48

print("Collector started at: ", time.strftime("%H:%M:%S %d-%m-%Y"))

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 2303))
current_day = time.strftime("%d-%b-%Y")

with open("netflowData-" + current_day + ".csv", "a", encoding='utf8', newline='') as csv_file:
    writer = csv.writer(csv_file, delimiter=',')
    #line = "src, sport, packet, bytes, dst, dport, time"
    writer.writerow(["src", "sport", "packet", "bytes", "dst", "dport", "time"])

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
    print("%s:%s %s bytes -> %s:%s" % (nfdata['saddr'], nfdata['sport'],
                                       nfdata['bcount'], nfdata['daddr'],
                                       nfdata['dport']))
    current_day = time.strftime("%d-%b-%Y")
    #print(current_day)
    with open("netflowData-" + current_day + ".csv", "a", encoding='utf8', newline='') as csv_file:
        writer = csv.writer(csv_file, delimiter=',')
        line = (nfdata['saddr'], nfdata['sport'],
                nfdata['pcount'], nfdata['bcount'],
                nfdata['daddr'], nfdata['dport'],
                nfdata['stime'], time.strftime("%H"))
        writer.writerow(line)
    #print("Wrote data to netflowData-" + current_day + ".csv at " + time.strftime("%H:%M:%S %d-%m-%Y"))
import requests
from config import *
import sqlite3
from flask import Flask, render_template,  request
app = Flask(__name__)

# Edit database file to reflect the right name/location of the netflow DB
conn = sqlite3.connect('netflow2.db')
conn.row_factory = sqlite3.Row
#conn.row_factory = sqlite3.Row
c = conn.cursor()
print("Deleting rows...")
# Blacklist considers Google DNS malicious.. cuz.. bad guys use it...
# Remove it from our database..
c.execute("DELETE FROM shodan WHERE dest=?", ("8.8.8.8",))
conn.commit()

# Prints all of the junk in the shodan table.. for debugging.
for i in c.execute("SELECT * FROM shodan"):
    for j in i:
        pass
        #print(j)
c.execute("SELECT name FROM sqlite_master WHERE type='table';")
#print(c.fetchone())
numSamples = 0
'''
# Converts 
def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d
'''

portNumber = "*"
def getData():
    global result1
    conn = sqlite3.connect('netflow2.db')
    #conn.row_factory = sqlite3.Row
    c = conn.cursor()
    #print(numSamples)
    c.execute("SELECT COUNT(*) FROM (SELECT DISTINCT dest, src FROM shodan LIMIT ?)", (numSamples,))
    unique = c.fetchall()
    for row in unique:
        print("Total unique IP Addresses: " + str(row[0]))
        unique_IPs = str(row[0])
    bytes = 0
    #c.execute("SELECT * FROM traffic WHERE src!=? ORDER BY time DESC LIMIT ?", (home, numSamples))
    c.execute("SELECT * FROM shodan ORDER BY time DESC LIMIT ?", (numSamples,))
        #print(result1)
    result1 = [i for i in c.fetchall()]
    #for i in result1:
        #print(i)
    #print(result1)
    print("Outbound: " + humansize(bytes))
    outbound = humansize(bytes)
    bytes = 0
    print(portNumber)
    for row in c.execute("SELECT * FROM shodan WHERE dest!=? AND dport=? ORDER BY time DESC LIMIT ?", (home, portNumber, numSamples)):
        totalbytes = int(row[3]) * int(row[2])
        bytes = bytes + totalbytes
        result2 = c.fetchall()
        #print(result2)
        result2 = {item[6]: item for item in result2}

    print("Inbound: " + humansize(bytes))
    inbound = humansize(bytes)
    #print(inbound.split()[0])
    total = float(inbound.split()[0]) + float(outbound.split()[0])
    #print(str(total))
    return unique_IPs, outbound.split()[0], outbound.split()[1], \
           inbound.split()[0], inbound.split()[1], str(total)

try:
    home = requests.get('http://ipquail.com/ip').text.strip("\n\r")
    print(home)
except:
    home = static_ip

suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

# Sweet function that converts bytes into readable form
def humansize(nbytes):
    i = 0
    while nbytes >= 1024 and i < len(suffixes)-1:
        nbytes /= 1024.
        i += 1
    f = ('%.2f' % nbytes).rstrip('0').rstrip('.')
    return '%s %s' % (f, suffixes[i])

# DO MATH.
def sqlStats():
    #for row in c.execute("SELECT COUNT (DISTINCT src) FROM traffic"):
    for row in c.execute("SELECT COUNT(*) FROM (SELECT DISTINCT dest, src FROM shodan)"):
        print("Total unique IP Addresses: " + str(row[0]))
        unique_IPs = str(row[0])
    bytes = 0

    for row in c.execute("SELECT * FROM shodan WHERE src=?", (home,)):
        totalbytes = int(row[3]) * int(row[2])
        bytes = bytes + totalbytes
    print("Outbound: " + humansize(bytes))
    outbound = humansize(bytes)
    bytes = 0
    for row in c.execute("SELECT * FROM shodan WHERE src!=?", (home,)):
        totalbytes = int(row[3]) * int(row[2])
        bytes = bytes + totalbytes
    print("Inbound: " + humansize(bytes))
    inbound = humansize(bytes)
    return unique_IPs, outbound, inbound

#sqlStats()

def maxRowsTable():
    for row in c.execute("SELECT COUNT(time) FROM shodan"):
        maxNumberRows=row[0]
    return maxNumberRows

## Flask Web Page Handling
@app.route("/")
def index():
    unique_IPs, outbound, outlabel, inbound, inlabel, total = getData()
    iframe = 'iframe.html'
    templateData = {
        'unique' : unique_IPs,
        'outbound' : outbound,
        'inbound' : inbound,
        'total' : total,
        'outlabel' : outlabel,
        'inlabel' : inlabel,
        'result1': result1,
        'iframe' : iframe
    }
    return render_template('index.html', **templateData)

@app.route('/', methods=['POST'])
def formPost():
    global numSamples
    global portNumber
    global IPAddress

    try:
        portNumber = int(request.form['portNumber'])
    except:
        portNumber = 8888
    try:
        numSamples = int(request.form['numSamples'])
    except:
        numSamples = "1000000000"
    try:
        IPAddress = str(request.form['IPAddress'])
    except:
        IPAddress = "*"
    numMaxSamples = maxRowsTable()
    if (int(numSamples) > int(numMaxSamples)):
        numSamples = (int(numMaxSamples) -1)
    unique_IPs, outbound, outlabel, inbound, inlabel, total = getData()
    templateData = {
        'unique': unique_IPs,
        'outbound': outbound,
        'inbound': inbound,
        'total': total,
        'outlabel': outlabel,
        'inlabel': inlabel,
        'result1': result1
    }
    return render_template('index.html', **templateData)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)

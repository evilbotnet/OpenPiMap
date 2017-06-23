import csv
import geoip2.database
import folium
from folium.element import IFrame
import os
import time
import shodan
import requests
import numpy as np
from folium.plugins import MarkerCluster
import matplotlib.pyplot as plt
from collections import Counter
from multiprocessing.dummy import Pool as ThreadPool, freeze_support
from itertools import repeat
from twilio.rest import TwilioRestClient
start_time = time.time()
API_KEY = 'INSERT SHODAN API KEY'
api = shodan.Shodan(API_KEY)
global external_ips, internal_ips, country_array, state_array, city_array, \
    latitude_array, longitude_array, location_array, hosts, ports, geodata, \
    lat, long, color, INBYTES, OUTBYTES, DATA, BYTES, md, oBL, CIA, noDNS, \
    TITLES, daily_in, daily_out, TIME
TIME = []

try:
    home = requests.get('http://ipquail.com/ip')
except:
    pass

malwaredomains_url = 'http://www.malwaredomainlist.com/hostslist/ip.txt'
openBL_url = 'http://www.openbl.org/lists/base_30days.txt'
CIArmy_url = 'http://cinsscore.com/list/ci-badguys.txt'
nothinkDNS_url = 'http://www.nothink.org/blacklist/blacklist_malware_dns.txt'
md = ''
oBL = ''
CIA = ''
noDNS = ''
try:
    malwaredomains = requests.get(malwaredomains_url, headers={'User-agent': 'evilbotnet.com -- InfoSec Research'})
    md = (malwaredomains.text).split('\r\n')
# print(md)
    openBL = requests.get(openBL_url, headers={'User-agent': 'evilbotnet.com -- InfoSec Research'})
    oBL = (openBL.text).split('\n')
# print(oBL)
    CIArmy = requests.get(CIArmy_url, headers={'User-agent': 'evilbotnet.com -- InfoSec Research'})
    CIA = (CIArmy.text).split('\n')
# print(CIA)
    nothinkDNS = requests.get(nothinkDNS_url, headers={'User-agent': 'evilbotnet.com -- InfoSec Research'})
    noDNS = (nothinkDNS.text).split('\n')
except:
    pass
badguys = []
compromise = []
compromise_custom = []
biglist = md + oBL + noDNS + CIA

def _csvParse(inputfile, home):
    f = open(inputfile)
    #badPorts = [21,22,23,2323,3306,3389,5358,7547]
    badPorts = [21,22,23,3306,3389]
    csv_file = csv.reader(f, delimiter=',')
    next(csv_file)
    inbytes = []
    outbytes = []
    for row in csv_file:
        if row:
            local_bytes = []
            src = row[0]
            sport = row[1]
            packets = row[2]
            bytes = row[3]
            dst = row[4]
            dport = row[5]
            uptime = row[6]
            local_bytes.append(bytes)
            if src != home:
                external_ips.append(src)
                ports.append(dport)
                inbytes.append(int(bytes))
                TIME.append(int(uptime))
            if src == home:
                internal_ips.append(dst)
                outbytes.append(int(bytes))
                TIME.append(int(uptime))
            if (int(dport) in badPorts) and (src != home):
                hosts.append(src)
                compromise_custom.append(tuple([src, dport]))
            if (int(sport) in badPorts) and (src == home):
                hosts.append(dst)
                compromise_custom.append(tuple([dst, sport]))


    INBYTES.append(sum(inbytes)/(1024*1024))
    OUTBYTES.append(sum(outbytes)/(1024*1024))
    DATA.append(sum(inbytes + outbytes))
    uniq_in_ips = set(internal_ips)
    uniq_ex_ips = set(external_ips)
    TITLES.append(inputfile[-15:-9])
    daily_out.append(len(uniq_ex_ips))
    daily_in.append(len(uniq_in_ips))
    #print("Inbound: %s" % (len(uniq_ex_ips)))
    #print("Outbound: %s" % (len(uniq_in_ips)))

def _geolocate(iplist):
    if os.name == 'nt':
        #print('Windows')
        reader = geoip2.database.Reader('C:\GeoLite2\GeoLite2-City.mmdb')
    else:
        #print('Linux')
        reader = geoip2.database.Reader('/root/GeoLite2/GeoLite2-City.mmdb')

    for ip in set(iplist):
        try:
            response = reader.city(ip)
            country_name = response.country.name
            state = response.subdivisions.most_specific.name
            city = response.city.name
            latitude = response.location.latitude
            longitude = response.location.longitude
            lat.append(latitude)
            long.append(longitude)
            country_array.append(country_name)
            state_array.append(state)
            hosts.append(ip)
            color.append('red')
        except:
            pass

def _folium(outfile):
    colors = list(zip(color))
    locations = list(zip(lat, long))
    popups = []
    popup_list = list(zip(hosts, country_array, state_array))
    for i in popup_list:
        shodan_data = []
        try:
            host = api.host(i[0])
            country = i[1]
            shodan_ip = host['ip_str']
            shodan_org = str(host.get('org', 'n/a'))
            shodan_os = str(host.get('os', 'n/a'))
            for item in host['data']:
                shodan_ports = "Port: %s <br>Banner: %s <br>" % (item['port'], item['data'])
                s1 = shodan_ports.replace("\n", "<br />")
                s = s1.replace("\r", "<br />")
                shodan_data.append(s)
                time.sleep(2)
        except shodan.APIError as e:
            print(e.value)
            shodan_ip = i[0]
            country = i[1]
            shodan_org = "No data available"
            shodan_os = "No data available"
            shodan_data = "--No data available--"

        html = """
            <p>IP:
            """ + shodan_ip + """
            </p>
            <p>Country:
            """ + country + """
            </p>
            <p>Organization:
            """ + shodan_org + """
            </p>
            <p>OS:
            """ + shodan_os + """
            </p>
            <p> """ + str(shodan_data)[2:-2] + """ </p>
            """
        iframe = IFrame(html=html, width=300, height=300)
        popups.append(iframe)
    m = folium.Map(location=[np.mean(lat), np.mean(long)], tiles='cartodbdark_matter', zoom_start=2)
    m.add_child(MarkerCluster(locations=locations, popups=popups, icons=color))
    m.save(outfile)

def _blackList(hosts):
    global compromise

    print("Parsing through %s suspect IP addresses." % (len(set(biglist))))
    for host in set(hosts):
        if host in set(biglist):
            # print("Bad Guy Found:")
            compromise.append(host)
            # print(host)
            if host in internal_ips:
                print("ALERT ALERT ALERT")
                print(host)
    compromise = compromise + compromise_custom
    print("Found %s bad guys" % len(set(compromise)))
    if not compromise:
        print("No malicious IPs were found")
        print("Checked against %s IPs." % len(biglist))

def _pieChart(variable, title, n, outfile):
    labels = []
    sizes = []
    legend = []
    n_groups = n
    explode_array = [0, 0, 0.05, 0.05, 0.1, 0.1, 0.2, 0.3, 0.4, 0.6]
    explode = explode_array[:n_groups]
    portcount = Counter(variable)
    most_common = portcount.most_common(n=n_groups)
    fig = plt.figure(4, figsize=(4,5), facecolor="black")
    ax = fig.add_subplot(211)

    for x, y in most_common:
        #print(x, y)
        labels.append(x)
        sizes.append(y)
        legend.append(("%-7s: %-4s") % (x,y))
    #plt.gca().axis("equal")
    ax.set_title(title, color="white")
    ax.axis("equal")
    pie = ax.pie(sizes, startangle=0, explode=explode)
    ax2 = fig.add_subplot(212)
    ax2.axis("off")
    ax2.legend(pie[0], legend, loc="center", fontsize=10,
           bbox_transform=plt.gcf().transFigure)
    plt.tight_layout()
    #plt.show()
    plt.savefig(outfile)
    plt.clf()

def _barChart(yValues, xValues, outfile):
    fig = plt.figure(figsize=(15,5), facecolor="black", edgecolor="white")
    ax = fig.add_subplot(111)
    ax.tick_params(axis="y", colors="black")
    N = len(yValues)
    menMeans = yValues[:N]
    # menStd = [2,3,4,1,2]
    ind = np.arange(N)
    width = 0.75
    rects1 = ax.bar(ind, menMeans, width=width, color='black', error_kw=dict(elinewidth=2, ecolor='red'))
    ax.set_xlim(-width, len(ind) + width)
    # ax.set_ylim(0,45)
    ax.set_ylabel('MegaBytes')
    ax.set_xlabel('Date')
    ax.set_title('Megabytes over time')
    xTickMarks = xValues
    ax.set_xticks(ind)
    xtickNames = ax.set_xticklabels(xTickMarks)
    plt.setp(xtickNames, rotation=45, fontsize=10)
    #plt.show()
    plt.savefig(outfile)
    #plt.savefig()

def _initialize():
    global external_ips, internal_ips, country_array, state_array, city_array, \
        latitude_array, longitude_array, location_array, hosts, ports, geodata, \
        lat, long, color, INBYTES, OUTBYTES, DATA, BYTES, md, oBL, CIA, noDNS, TITLES, \
        compromise, daily_in, daily_out, message
    message = []
    daily_in = []
    daily_out = []
    ports = []
    internal_ips = []
    country_array = []
    state_array = []
    external_ips = []
    geodata = []
    lat = []
    long = []
    hosts = []
    color = []
    INBYTES = []
    OUTBYTES = []
    DATA = []
    TITLES = []
    compromise = []

directory = '.'
files = sorted([f for f in os.listdir(directory) if f.startswith('netflowData-') and f.endswith('.csv')])
last24 = files[-2:-1]
last72 = files[-4:-1]
lastWeek = files[-8:-1]
last30 = files[-31:-1]

def _lastN(infiles, outfile):
    for item in infiles:
        #print(item)
        _csvParse(item, home)
    _blackList(hosts=set(internal_ips + external_ips))
    _geolocate(compromise)
    print("TOTAL BAD GUYS: %s" % len(hosts))
    #_pieChart(variable=ports, title='Top Ports', n=10,outfile=outfile[:-5] + '.jpg')
    #_pieChart(variable=external_ips, title='Top Ports', n=10,outfile=outfile[:-5] + '2.jpg')
    #_barChart(yValues=(DATA), xValues=sorted(TITLES), N=14,outfile=outfile[:-5] + '.jpg')
    #_folium(outfile=outfile)
    #_shodan(iplist=hosts, filename='shodan.txt')
    _initialize()


def _shodan(iplist, filename):
    f = open(filename, "w+")
    for ip in iplist:
        try:
            host = api.host(ip)
            print("IP: %s\nOrganization: %s\nOperating System: %s\n" % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))
            f.write("IP: %s\nOrganization: %s\nOperating System: %s\n" % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))
            for item in host['data']:
                print("Port: %s\nBanner: %s\n" % (item['port'], item['data']))
                f.write("Port: %s\nBanner: %s\n" % (item['port'], item['data']))
                time.sleep(5)
        except shodan.exception.APIError as e:
            print(e.value)
            continue
    f.close()

def _shodan2(ip):
    host = api.host(ip)
    shodan_data = []
    shodan_host = "IP: %s\nOrganization: %s\nOperating System: %s\n" % (host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a'))
    shodan_data.append(shodan_host)
    for item in host['data']:
        shodan_ports = "Port: %s\nBanner: %s\n" % (item['port'], item['data'])
        shodan_data.append(shodan_ports)
    return shodan_data

def _lastHour(infiles, outfile):
    for item in infiles:
        _csvParse(item, home)
        print(TIME[-1])
        hour = (TIME[-1] - 3600000)
        print(hour)
        i = 0
        index = 0
        for position, item in enumerate(TIME):
            if item > hour and i == 0:
                index = (int(position))
                i = 1
        print(index)
        #_blackList(hosts=set(internal_ips[int(index):] + external_ips[int(index):]))
        _geolocate(iplist=set(internal_ips[int(index):] + external_ips[int(index):]))
        print(len(internal_ips))
        print("TOTAL BAD GUYS: %s" % len(hosts))
        #_folium(outfile=outfile)

def _sendText(message):
    account_sid = "TWILIO SID"
    auth_token = "TWILIO AUTH_TOKEN"
    client = TwilioRestClient(account_sid, auth_token)
    message = client.messages.create(to='+RECV NUMBER', from_='+TWILIO NUMBER', body=message)

def _multiThreadedTest(infiles):
    arg1 = []
    arg2 = home
    for item in infiles:
        arg1.append(item)
    pool = ThreadPool(len(arg1))
    pool.starmap(_csvParse, zip(arg1, repeat(arg2)))
    print("Parsed through %d IP addresses." % (len(set(internal_ips + external_ips))))
    _blackList(hosts=set(internal_ips + external_ips))
    _geolocate(hosts)
#print(privateIP.text)
#_initialize()
#_multiThreadedTest(last30)
#res_list = [x[0] for x in compromise]
#_barChart(yValues=(DATA), xValues=sorted(TITLES),outfile="bar.png")
#text_file = open("badguys.txt", "w")
#for i in biglist:
#    text_file.write("%s\n" % (i))
#_pieChart(ports, "Top ports", 10, "topports.png")
#_folium("test.html")
biglist = []
with open ('badguys.txt', 'r') as myfile:
    for line in myfile:
        #print(line.strip('\n'))
        biglist.append(line.strip('\n'))


#print(len(biglist))
_initialize()
_multiThreadedTest(last30)
_folium('lastMonth.html')
_barChart(DATA, TITLES, 'bar.png')
_pieChart(ports, "Top Ports", 10, "topports.png")
freeze_support()
print("time elapsed: {:.2f}s".format(time.time() - start_time))
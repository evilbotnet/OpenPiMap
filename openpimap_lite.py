import csv
import geoip2.database
import folium
import os
import time
import shodan
import requests
from config import *
from folium.plugins import MarkerCluster

start_time = time.time()
api = shodan.Shodan(API_KEY)
TIME = []

try:
    home = requests.get('http://ipquail.com/ip').text.strip("\n\r")
    print(home)
except:
    home = static_ip

malwaredomains_url = 'http://www.malwaredomainlist.com/hostslist/ip.txt'
openBL_url = 'http://www.openbl.org/lists/base_30days.txt'
CIArmy_url = 'http://cinsscore.com/list/ci-badguys.txt'
nothinkDNS_url = 'http://www.nothink.org/blacklist/blacklist_malware_dns.txt'

try:
    malwaredomains = requests.get(malwaredomains_url, headers={'User-agent': 'evilbotnet.com -- InfoSec Research'})
    md = malwaredomains.text.split('\r\n')
    openBL = requests.get(openBL_url, headers={'User-agent': 'evilbotnet.com -- InfoSec Research'})
    oBL = openBL.text.split('\n')
    emergeThreat = requests.get('https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
                                headers={'User-agent': 'evilbotnet.com -- InfoSec Research'})
    eT = emergeThreat.text.split('\n')
    CIArmy = requests.get(CIArmy_url, headers={'User-agent': 'evilbotnet.com -- InfoSec Research'})
    CIA = CIArmy.text.split('\n')
    nothinkDNS = requests.get(nothinkDNS_url, headers={'User-agent': 'evilbotnet.com -- InfoSec Research'})
    noDNS = nothinkDNS.text.split('\n')
except:
    pass
badguys = []
compromise = []
compromise_custom = []
biglist = md + oBL + noDNS + CIA + eT


def _csvparse(inputfile, ip_address):
    f = open(inputfile)
    # badPorts = [21,22,23,2323,3306,3389,5358,7547]
    csv_file = csv.reader(f, delimiter=',')
    next(csv_file)
    inbytes = []
    outbytes = []
    for row in csv_file:
        if row:
            local_bytes = []
            src = row[0]
            # sport = row[1]
            # packets = row[2]
            bytes = row[3]
            dst = row[4]
            dport = row[5]
            uptime = row[6]
            local_bytes.append(bytes)
            if src != ip_address:
                external_ips.append(src)
                ports.append(dport)
                inbytes.append(int(bytes))
                TIME.append(int(uptime))
            if src == ip_address:
                internal_ips.append(dst)
                outbytes.append(int(bytes))
                TIME.append(int(uptime))
                # if (int(dport) in badPorts) and (src != home):
                #     hosts.append(src)
                #     compromise_custom.append(tuple([src, dport]))
                # if (int(sport) in badPorts) and (src == home):
                #     hosts.append(dst)
                #     compromise_custom.append(tuple([dst, sport]))
    INBYTES.append(sum(inbytes) / (1024 * 1024))
    OUTBYTES.append(sum(outbytes) / (1024 * 1024))
    DATA.append(sum(inbytes + outbytes))
    uniq_in_ips = set(internal_ips)
    uniq_ex_ips = set(external_ips)
    TITLES.append(inputfile[-15:-9])
    daily_out.append(len(uniq_ex_ips))
    daily_in.append(len(uniq_in_ips))


def _geolocate(iplist):
    if os.name == 'nt':
        reader = geoip2.database.Reader('D:\PycharmProjects\openpimap\GeoLite2-City.mmdb')
    else:
        reader = geoip2.database.Reader('/root/GeoLite2/GeoLite2-City.mmdb')

    for ip in set(iplist):
        try:
            response = reader.city(ip)
            country_name = response.country.name
            state = response.subdivisions.most_specific.name
            latitude = response.location.latitude
            longitude = response.location.longitude
            lat.append(latitude)
            long.append(longitude)
            country_array.append(country_name)
            state_array.append(state)
            hosts.append(ip)
            color.append('red')
        except Exception as e:
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
        except shodan.APIError as e:
            shodan_ip = i[0]
            country = i[1]
            shodan_org = "No Shodan Data Found"
            shodan_os = "No Shodan Data Found"
            shodan_data = "--No Shodan Data Found"
        try:
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
        except TypeError:
            html = """
            <p>IP:
            """ + "none" + """
            </p>
            <p>Country:
            """ + "none" + """
            </p>
            <p>Organization:
            """ + "none" + """
            </p>
            <p>OS:
            """ + "none" + """
            </p>
            
            """
        iframe = folium.IFrame(html=str(html), width=300, height=300)
        popups.append(iframe)
        time.sleep(0.75)

    m = folium.Map(location=[0, 0], tiles='cartodbdark_matter', zoom_start=2)
    m.add_child(MarkerCluster(locations=locations, popups=popups, icons=color))
    m.save(outfile)


def _blacklist(suspects):
    global compromise
    for host in set(suspects):
        if host in set(biglist):
            compromise.append(host)


def _initialize():
    global external_ips, internal_ips, country_array, state_array, city_array, \
        latitude_array, longitude_array, location_array, hosts, ports, geodata, \
        lat, long, color, INBYTES, OUTBYTES, DATA, BYTES, md, oBL, CIA, noDNS, TITLES, \
        compromise, daily_in, daily_out, message, eT
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
last24 = files[0:1]
last72 = files[0:3]
lastWeek = files[0:8]
last30 = files[0:31]


def _lastn(infiles, output):
    for item in infiles:
        _csvparse(item, home)
    _blacklist(set(internal_ips + external_ips))
    _geolocate(compromise)
    _folium(outfile=output)
    _initialize()

_initialize()
_lastn(last24, output="last24.html")
_lastn(last72, "last72.html")
_lastn(lastWeek, "lastWeek.html")
_lastn(last30, "lastMonth.html")
print("time elapsed: {:.2f}s".format(time.time() - start_time))

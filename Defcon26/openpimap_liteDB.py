import datetime
import geoip2.database # Used for mapping IP -> location. Requires offline GeoLite2 database
import folium # Mapping application for data visualization
import os # Checks for linux/windows for filepath options
import time # For retrieving current date and checking script runtime
import shodan # OSINT portion. Queries for banner information from Shodan.io
import requests # Retrieves watchlists and makes web requests...
from config import * # Includes sensitive API information in separate file for security purposes
from folium.plugins import MarkerCluster # Marker portion for dots on the Folium map
import sqlite3 # SQLlite interface for SQL database
from ipaddress import ip_network # ip_address, IPv4Address, IPv4Network

# Replace with the name of the SQL database created by the NetFlow collector service
conn = sqlite3.connect('netflow2.db')
conn.row_factory = lambda cursor, row: row[0]
c = conn.cursor()

# Creates all of the blacklists!!
blacklist = []
bad = []
start_time = time.time()
api = shodan.Shodan(API_KEY)
TIME = []
firehol = "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level4.netset"
firehol_abusers30day = "https://iplists.firehol.org/files/firehol_abusers_30d.netset"
try:
    firehol_list = requests.get(firehol, headers={'User-agent': 'evilbotnet.com -- InfoSec Research'}).text.split('\n')
    #print(firehol_list)
    abuser_list = requests.get(firehol_abusers30day, headers={'User-agent': 'evilbotnet.com -- InfoSec Research'}).text.split('\n')
    #print(abuser_list)
    #rawdata = firehol_list + abuser_list
    rawdata = firehol_list
    for i in rawdata:
        try:
            ip_network(i)
            #print(i)
            blacklist.append(i)
        except Exception as e:
            #print(e)
            pass
except Exception as e:
    #print(e)
    pass

#print(blacklist)

# SLOW! ...like 3 queries a MINUTE! DO NOT USE unless you really want this data...
def vtLookup(ip):
    apikey = VirusTotalAPIKey
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey': apikey, 'ip': ip}
    response = requests.get(url, params=params)
    data = response.json()
    sorted_date = sorted(data['resolutions'],
                         key=lambda x: datetime.datetime.strptime(x['last_resolved'], '%Y-%m-%d %H:%M:%S'),
                         reverse=True)
    url = sorted_date[0]['hostname']
    print(ip + ": " + url)
    return url

conn.execute("CREATE TABLE IF NOT EXISTS shodan (src text, sport int, packet int, \
    bytes int, dest text, dport int , time text)")

try:
    home = requests.get('http://ipquail.com/ip').text.strip("\n\r")
    print(home)
except:
    home = static_ip

#unique_IPs = c.execute("SELECT DISTINCT dest FROM traffic").fetchall()
#print(len(unique_IPs))
unique_src = (c.execute("SELECT DISTINCT src FROM traffic").fetchall())
unique_dest = (c.execute("SELECT DISTINCT dest FROM traffic").fetchall())
#print(len(unique_src))
#print(len(unique_dest))


iplist=(sorted(set(unique_dest + unique_src)))

print("Found a total of {} ip addresses.".format(len(iplist)))
print("List of IP's: {}".format(iplist))


# Uhh... wat?
# TODO: Fix this garbage...
#reserved_networks = [x for x in [blacklist]]
#print(reserved_networks)
reserved_networks = blacklist
reserved_networks = [x for x in reserved_networks if x !="8.8.8.8" ]
for ip in iplist:
    if any((ip in net) for net in reserved_networks) == True:
        bad.append(ip)
        print("Found badguy at " + str(ip))

for ip in bad:
    try:
        time_var = conn.execute("SELECT time FROM shodan WHERE src=? OR dest=?", (ip,ip))
        #print(time_var)
        time_var = c.fetchone()
        if time_var is None:
            print("Insterting " + ip + " into SQL database")
            conn.execute("INSERT INTO shodan SELECT * FROM traffic WHERE src=? OR dest=?", (ip, ip))
            conn.commit()
        print(time_var)
        conn.execute("SELECT * FROM shodan WHERE src=? OR dest=? AND time=?",(ip,ip,time_var))
        if c.fetchone() is None:
            print("Insterting " + ip + " into SQL database")
            conn.execute("INSERT INTO shodan SELECT * FROM traffic WHERE src=? OR dest=?", (ip,ip))
            conn.commit()
        else:
            print("Already found value.. passing.")
    except Exception as e:
        pass
        #print(e)
conn.execute("SELECT * FROM shodan")
#print(c.fetchall())

# Geolocates the IP addresses using the GeoLite2-City.mmdb local database
# Edit the file path to reflect the local database
# Download the database at https://dev.maxmind.com/geoip/geoip2/geolite2/
def _geolocate(iplist):
    print("Starting geolocation...\n")
    # Update filepaths to match the location of the GeoLite2-City.mmdb database
    if os.name == 'nt':
        reader = geoip2.database.Reader('D:\PycharmProjects\openpimap\GeoLite2-City.mmdb')
    else:
        reader = geoip2.database.Reader('/root/GeoLite2/GeoLite2-City.mmdb')

    for ip in iplist:
        print(ip)
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
            print(e)

# Maps everything in a pretty map. Major kudos to Folium for awesome designs out of the box.
def _folium(outfile):
    print("Starting mapping...")
    #colors = list(zip(color))
    locations = list(zip(lat, long))
    popups = []
    popup_list = list(zip(hosts, country_array, state_array))
    for i in popup_list:
        print("Trying " + str(i))
        shodan_data = []
        try:
            host = api.host(i[0])
            print(host)
            country = i[1]
            shodan_ip = host['ip_str']
            shodan_org = str(host.get('org', 'n/a'))
            shodan_os = str(host.get('os', 'n/a'))
            hostname = str(host.get('hostnames', 'n/a'))
            print(hostname)
            for item in host['data']:
                shodan_ports = "Port: %s <br>Banner: %s <br>" % (item['port'], item['data'])
                s1 = shodan_ports.replace("\n", "<br />")
                s = s1.replace("\r", "<br />")
                shodan_data.append(s)
                print(shodan_data)

        except shodan.APIError as e:
            shodan_ip = i[0]
            country = i[1]
            shodan_org = "No Shodan Data Found"
            shodan_os = "No Shodan Data Found"
            shodan_data = "--No Shodan Data Found"
            hostname = "No hostname found"
        try:
            html = """
            <p>IP:
            """ + shodan_ip + """
            </p>
            <p>URL:
            """ + hostname + """
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

    m = folium.Map(location=[0, 0], tiles='cartodbdark_matter', zoom_start=3)
    m.add_child(MarkerCluster(locations=locations, popups=popups, icons=color))
    m.save(outfile)


# Initializes all of the variables..
# TODO: probably a much more efficient way to do this..
def _initialize():
    print("Initializing all of the global variables and lists...\n")
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

_initialize()
_geolocate(iplist=bad)
_folium(outfile='index.html')

print("time elapsed: {:.2f}s".format(time.time() - start_time))

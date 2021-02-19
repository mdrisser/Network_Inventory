#!/usr/bin/python3

import sys
import csv

hosts = {}


# FUNCTION: print_usage()
# PARAMS: None
# RETURN: None. Prits message to console indicating usage of
#     the script command
def print_usage():
    print(f"USAGE: {sys.argv[0]} TARGET CSV_LOCATION")


# FUNCTION: check_State()
# PARAMS: ip = IP Address to ping, using pythonping, to
#    determine if the host is UP or DOWN
# RETURN: String, UP or DOWN, indicating state of host
def check_state(ip):
    from pythonping import ping

    state = ""
    resp = ping(ip, size=10, count=3)

    if "Reply from" in str(resp):
        state = "UP"
    else:
        state = "DOWN"
    
    return state


# FUNCTION: check_range()
# PARAMS: target = subnet to scan
#         assoc_array = dictionary to append the results to
# RETURN: None, appends scan results to supplied dictionary
def check_range(target, assoc_array):
    import socket

    octets = target.split('.')
    rng = octets[3].split('-')

    for i in range(int(rng[0]),int(rng[1])+1):
        ip = octets[0] + '.' + octets[1] + '.' + octets[2] + '.' + str(i)
        state = check_state(ip)
        print(f"{ip}: {state}")

        try:
            host = socket.gethostbyaddr(ip)
        except:
            host = ("N/A", [], [ip])
        
        if host[0] == "N/A":
            hostname = "N/A"
            domain = "N/A"
        else:
            dns = host[0].split('.')
            hostname = dns[0]
            domain = '.'.join(dns[1:])

        if state == "UP":
            os_res = check_os(ip)
            os = os_res[1]['name']
        else:
            os = "N/A"
        
        assoc_array[ip] = {"state": state, 'hostname': hostname, 'domain': domain, 'os': os}

        #return assoc_array


# FUNCTION: check_os()
# PARAMS: ip = IP Address to scan using nmap to check the OS and version
# RETURN: String containg the OS and version
def check_os(ip):
    import nmap3
    nmap = nmap3.Nmap()

    result = nmap.nmap_os_detection(ip)

    return result


# FUNCTION: scan_network()
# PARAMS: target = subnet to scan
# RETURN: Nothing
def scan_network(target):
    import ipaddress
    from pythonping import ping
    from nslookup import Nslookup as ns

    if "/" in target:
        net = ipaddress.IPv4Network(target)

        for n in net:
            ip = str(n)
            state = check_state(ip)
            print(f"{ip}: {state}")
            hosts[ip] = {"state": state, "hostname": hostname}
    elif "-" in target:
        #print("Something will go here")
        #sys.exit(1)
        print(f"Scanning {target}.....")
        check_range(target, hosts)
    else:
        state = check_state(target)
        print(f"{target}: {state}")
        hosts[target] = state


num_args = len(sys.argv)

if num_args == 1 or num_args > 3:
    print_usage()
    sys.exit(1)
else:
    target = sys.argv[1]

scan_network(target)

print(hosts)

# Data is a dictionary using the IP as the key and a sub-dictionary containing the actual data
# e.g.:
# '10.0.0.1': {
#   'state': 'UP',
#   'hostname': 'foo',
#   'domain': 'bar.local,
#   'os': 'Microsoft Windows 10 1703'
# }
# See assoc_array[ip] = ... in check_range() above

#TODO: Issues with writing the CSV. The CSV contains the numbers from
#the IP Address, seperated into individual elements, and no other data
with open(sys.argv[2], 'w') as f:
    csvout = csv.writer(f, delimiter='|')

    for row in hosts:
        csvout.writerow(row)
        print(row)

print()
print("DONE!")
#!/usrbinpython3

import untangle

# Path to nmap XML file
xml_file = "20201204-nmap-scan.xml"

# Create an nmap xml parser using untangle
nmapxml = untangle.parse(xml_file)

# Loop through the found hosts and extract the information we want
for host in nmapxml.nmaprun.host:
    try:
        starttime = host['starttime']
        
    except:
        continue
    
    status = host.status['state']
    
    # Get the IP Address
    for address in host.address:
        try:
            if host.address['addrtype'] == 'ipv4':
                ip_addr = host.address['addr']
        except:
            #ip_addr = '0.0.0.0'
            continue
    
    # Get the hostname
    try:
        hostname = host.hostnames.hostname['name']
    except:
        hostname = "NULL"

    print(f"{ip_addr} | {hostname} | {status}")


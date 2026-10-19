import nmap

## Scan the network, finding devices
def scan_network(network):
	nm = nmap.PortScanner()
	
	# Simple scan for hosts
	nm.scan(hosts=network, arguments="-sn")
	print("Hosts Found:")
	print(nm.all_hosts())
	print()
	
	# The Found devices	
	devices = []
	
	for host in nm.all_hosts():
		hostname = nm[host].hostname()
		
		os_name = "Unknown"
		mac = "Unknown"
		vendor = "Unknown"
		
		if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
			os_name = nm[host]['osmatch'][0]['name']
		
		# Get MAC address
		if 'addresses' in nm[host]:
			mac = nm[host]['addresses'].get("mac", "Unknown")
			
		# Get vendor
		if 'vendor' in nm[host] and nm[host]['vendor']:
			vendor = list(nm[host]['vendor'].values())[0]
		
		devices.append({
			"ip": host,
			"hostname": hostname,
			"os": os_name,
			"mac": mac,
			"vendor": vendor
		})
	
	return devices

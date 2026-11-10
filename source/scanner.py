import nmap

## Check for mac randomization, could affect trustworthiness 
def is_randomized_mac(mac):
	if not mac or mac == "Unknown":
		return None
	
	try:
		first_segment = int(mac.split(":")[0], 16)
		return bool(first_segment & 0b00000010)
	except (ValueError, IndexError):
		return None


## Scan the network, finding devices, then find more information on the found devices in a next step
def scan_network(network):
	## Step 1 - discovery
	discovery = nmap.PortScanner()
	
	# Simple scan for hosts
	discovery.scan(hosts=network, arguments="-sn")
	
	hosts = discovery.all_hosts()
	print("Hosts Found:")
	print(hosts)
	print()
	
	# The Found devices	
	devices = []
	
	if not hosts:
		return devices
	
	## Step 2 - OS fingerprinting
	fingerprint = nmap.PortScanner()
	
	fingerprint.scan(hosts=" ".join(hosts), arguments="-O -sV --top-ports 20")
	
	## Step 3 - Device info
	
	for host in hosts:
		hostname = discovery[host].hostname() or "Unknown"
		
		addresses = discovery[host].get("addresses", {})
		
		mac = addresses.get("mac", "Unknown")
		
		vendor_data = discovery[host].get("vendor", {})
		vendor = (
			next(iter(vendor_data.values()))
			if vendor_data else "Unknown"
		)
		
		# Default information
		os_name = "Unknown"
		os_accuracy = 0
		os_family = "Unknown"
		os_vendor = "Unknown"
		device_type = "Unknown"
		
		open_ports = []
		services = []
		
		
		
		# Take OS info from second scan
		if host in fingerprint.all_hosts():
			host_data = fingerprint[host]
			
			# OS Info
			os_matches = host_data.get("osmatch", [])
			
			if os_matches:
				# Best match is in position 0
				best_match = os_matches[0]
				
				# Grab the name and accuracy
				os_name = best_match.get("name", "Unknown")
				os_accuracy = int(best_match.get("accuracy", 0))
				
				os_classes = best_match.get("osclass", [])
				
				if os_classes:
					best_class = os_classes[0]
					
					os_family = best_class.get("osfamily", "Unknown")
					os_vendor = best_class.get("vendor", "Unknown")
					device_type = best_class.get("type", "Unknown")
				
			# MAC Info
			fingerprint_addresses = host_data.get("addresses", {})
			
			if mac == "Unknown":
				mac = fingerprint_addresses.get("mac", "Unknown")
				
			if vendor == "Unknown":
				fingerprint_vendor = host_data.get("vendor", {})
				
				if fingerprint_vendor:
					vendor = next(iter(fingerprint_vendor.values()))
			
			# Port and Services
			tcp_ports = host_data.get("tcp", {})
			
			for port, info in tcp_ports.items():
				state = info.get("state", "unknown")
				
				# Open ports
				if state == "open":
					port = int(port)
					open_ports.append(port)
					
					services.append({
						"port": port,
						"name": info.get("name", "Unknown"),
						"product": info.get("product", ""),
						"version": info.get("version", ""),
						"extra_info": info.get("extrainfo", "")
					})
		
		devices.append({
			"ip": host,
			"hostname": hostname,
			"mac": mac,
			"mac_randomized": is_randomized_mac(mac),
			"vendor": vendor,
			
			"os": os_name,
			"os_accuracy": os_accuracy,
			"os_family": os_family,
			"os_vendor": os_vendor,
			"device_type": device_type,
			
			"open_ports": open_ports,
			"services": services,
			"simulated": False
		})
	
	return devices

def evaluate_device(device):
	score = 100
	reasons = []
	observations = []
	
	hostname = device.get("hostname", "Unknown").lower()
	os_name = device.get("os", "Unknown").lower()
	os_family = device.get("os_family", "Unknown").lower()
	
	vendor = device.get("vendor", "Unknown")
	os_vendor = device.get("os_vendor", "Unknown")
	
	os_accuracy = device.get("os_accuracy", 0)
	
	mac = device.get("mac", "Unknown")
	mac_randomized = device.get("mac_randomized")
	
	open_ports = device.get("open_ports", [])
	services = device.get("services", [])
	
	# Check 1 - Device consistancy check
	# For Example an apple style hostname with linux os
	
	if("iphone" in hostname and os_family == "linux" and os_accuracy >= 90):
		score -= 25
		reasons.append("Apple style hostname but has linux fingerprint.")
	
	# Check 2 - OS Fingerprint Confidence
	if os_name == "unknown":
		observations.append("Unbale to identify operating system.")
		
	elif os_accuracy < 70:
		observations.append(f"OS fingerprint has relatively low accuracy ({os_accuracy}%).")
	
	elif os_accuracy >= 90:
		observations.append(f"Strong OS fingerprint match ({os_accuracy}%).")
		
	# Check 3 - MAC Address
	if mac == "Unknown":
		observations.append("Unable to identify MAC address.")
	
	if vendor == "Unknown":
		observations.append("Unable to identify device vendor.")
	
	if mac_randomized is True:
		observations.append("MAC address is locally administered; could be randomized.")
		
	# Check 4 - Vendor info
	virtual_vendor = ("virtualbox" in vendor.lower() or "pcs systemtechnik" in vendor.lower())
	
	if (vendor != "Unknown" and os_vendor != "Unknown" and not virtual_vendor):
		if vendor.lower() != os_vendor.lower():
			observations.append(f"MAC vendor ({vendor}) differs from OS fingerprint vendor ({os_vendor}).")
	
	# Check 5 - Network info
	if open_ports:
		observations.append(f"Discovered {len(open_ports)} open TCP port(s).")
	
	if services:
		service_names = [
			service["name"]
			for service in services
			if service.get("name")
		]
		
		if service_names:
			observations.append("Identified services: " + ", ".join(service_names))
			
	# Check 6 - Confidence Score
	confidence = 0
	
	# Basic device info
	if device.get("ip") != "Unknown":
		confidence += 10
	
	if hostname != "unknown":
		confidence += 10
	
	if mac != "Unknown":
		confidence += 20
	
	if vendor != "Unknown":
		confidence += 10
		
	# Os info
	if os_name != "unknown":
		confidence += 10
	
	if os_accuracy >= 70:
		confidence += 15
	
	if os_family != "unknown":
		confidence += 5
	
	# Network info
	if open_ports:
		confidence += 10
	
	if services:
		confidence += 10
		
	confidence = min(confidence, 100)
	
	# Check 7 - Final status
	score = max(0, min(score, 100))
	
	if score >= 80:
		status = "TRUSTWORTHY"
	elif score >= 60:
		status = "UNCERTAIN"
	else: 
		status = "SUSPICIOUS"
		
	return {
		"score": score,
		"confidence": confidence,
		"status": status,
		"reasons": reasons,
		"observations": observations
	}

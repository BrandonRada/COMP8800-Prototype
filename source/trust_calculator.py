def evaluate_device(device):
	score = 100
	reasons = []
	
	hostname = device["hostname"].lower()
	os_name = device["os"].lower()
	vendor = device["vendor"].lower()
	
	# This is an example of a suspicous device rule
	if "iphone" in hostname and "linux" in os_name:
		score -= 70
		reasons.append("Apple style hostname but has linux fingerprint.")
		
	if os_name == "unknown":
		score -= 20
		reasons.append("Unable to identify operating system.")
		
	if device["vendor"] == "Unknown":
		score -= 10
		reasons.append("Unable to identify device vendor.")
	
	if score >= 80:
		status = "TRUSTWORTHY"
	elif score >= 60:
		status = "UNCERTAIN"
	else: 
		status = "SUSPICIOUS"
		
	return {
		"score": score,
		"status": status,
		"reasons": reasons
	}

from scanner import scan_network
from trust_calculator import evaluate_device

print("\nProject Prototype\n")

while True:
	network = input("Enter network to scan (example: 192.168.56.0/24): ").strip()
	
	if "/" in network:
		break
	print("Invalid network format...\n")
	
devices = scan_network(network)

## Simulated Suspicious/Spoofed device, helpful to see what a suspicious device found would look like in the future
devices.append({
	"ip": "192.168.56.200",
	"hostname": "iPhone15",
	"mac": "AA:BB:CC:DD:EE:FF",
	"mac_randomized": True,
	"vendor": "Apple",
	"os": "Linux",
	"os_accuracy": 96,
	"os_family": "Linux",
	"os_vendor": "Linux",
	"device_type": "general purpose",
	"open_ports": [22, 80],
	"services": [
		{
			 "port": 22,
			 "name": "ssh",
			 "product": "OpenSSH",
			 "version": "9.0",
			 "extra_info": ""
		},
		{
			"port": 80,
			"name": "http",
			"product": "",
			"version": "",
			"extra_info": ""
		}
	],
	"simulated": True
})

trusted = 0
uncertain = 0
suspicious = 0

print("Devices Found: ", len(devices))

for d in devices:
	print(d)
	result = evaluate_device(d)
	
	if result["status"] == "TRUSTWORTHY":
		trusted += 1
	elif result["status"] == "UNCERTAIN":
		uncertain += 1
	else: 
		suspicious += 1
	
	
	print("=" * 60)
	print("IP: ", d["ip"])
	if d.get("simulated"):
		print("Device Type: SIMULATED TEST DEVICE")
		
	print("Hostname: ", d["hostname"])
	
	print("\n--- Device Identification ---")
	print("MAC Address:", d["mac"])
	print("MAC Vendor:", d["vendor"])
	print("MAC Randomized/Potentially Randomized:", d["mac_randomized"])
	
	print("\n--- OS Fingerprinting ---")
	print("Operating System:", d["os"])
	print("OS Accuracy:", str(d["os_accuracy"]) + "%")
	print("OS Family:", d["os_family"])
	print("OS Vendor:", d["os_vendor"])
	print("Device Type:", d["device_type"])
	
	print("\n--- Network Information ---")
	print("Open Ports:", d["open_ports"])
	
	if d["services"]:
		print("Services:")
		for service in d["services"]:
			print(
				f"  {service['port']}: "
				f"{service['name']} "
				f"{service['product']} "
				f"{service['version']}"
			)
	else:
		print("Services: None identified")
		
	
	print("\n--- Trust Assessment ---")
	print("Trust Score:", result["score"], "/ 100")
	print("Confidence Score:", result["confidence"], "/ 100")
	print("Status:", result["status"])
	
	if result["reasons"]:
		print("\nSuspicious Indicators:")
		for reason in result["reasons"]:
			print("-", reason)
			
	if result["observations"]:
		print("\nObservations:")
		for observation in result["observations"]:
			print("-", observation)
	print()
		
print("=" * 30)
print("Scan Summary")
print("=" * 30)

print("Devices Discovered:", len(devices))
print("Trustworthy Devices:", trusted)
print("Uncertain Devices:", uncertain)
print("Suspicious Devices:", suspicious)

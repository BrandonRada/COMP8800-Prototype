from scanner import scan_network
from trust_calculator import evaluate_device

print("\nProject Prototype\n")

while True:
	network = input("Enter network to scan (example: 192.168.56.0/24): ").strip()
	
	if "/" in network:
		break
	print("Invalid network format...\n")
	
devices = scan_network(network)
trusted = 0
uncertain = 0
suspicious = 0

## Simulated Suspicious/Spoofed device, helpful to see what a suspicious device found would look like in the future
devices.append({
	"ip": "192.168.56.200",
	"hostname": "iPhone15",
	"mac": "AA:BB:CC:DD:EE:FF",
	"vendor": "Apple",
	"os": "Linux"
})


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
	print("Hostname: ", d["hostname"])
	print("OS: ", d["os"])
	print("MAC Address: ", d["mac"])
	print("Vendor: ", d["vendor"])
	
	print()
	print("Trust Score: ", result["score"])
	print("Status: ", result["status"])
	
	if result["reasons"]:
		print("Reasons: ")
		for reason in result["reasons"]:
			print("- ", reason)
			
	print()
	
		
print("=" * 30)
print("Scan Summary")
print("=" * 30)
print("Devices Discovered:", len(devices))
print("Trustworthy Devices:", trusted)
print("Uncertain Devices:", uncertain)
print("Suspicious Devices:", suspicious)

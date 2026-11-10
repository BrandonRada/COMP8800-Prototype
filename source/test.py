import nmap

nm = nmap.PortScanner()

nm.scan(
	hosts="192.168.56.1",
	arguments="-O"
)

print(nm["192.168.56.1"])

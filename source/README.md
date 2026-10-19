Steps to Run:

Requirements:
Software:
	Python 3
	Nmap
	python-nmap library

Installation:
	pip install python-nmap
Or in my case:
	sudo apt install python3-nmap

Verify that Nmap is installed:
	nmap --version

Running the Prototype:
1. Open a terminal

2. Navigate to the project directory (source) if not already inside of it
	cd source
	
3. Run the program
	python main.py
	
4. When prompted, enter a network range to scan
	In my case:
	192.168.56.0/24
	
5. The prototype will:
	Discover devices
	Collect available device information
	Calculate trust scores
	Generate a network summary

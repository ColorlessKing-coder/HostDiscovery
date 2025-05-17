

# 🐍  HostDiscovery

Welcome to  ** HostDiscovery Program **! 🎯  

This script will provide you with information about the devices located within the network. ✨

This tool is not as advanced as tools like nmap.

Port detection and service detection have been kept completely simple. A thorough detection has not been made; it has been done superficially.


---


- 🐍 Python scripts (`.py` files)
- 📄 A short description or documentation
- ⚙️ Optionally, requirements or config files

---

## 🚀 How to Use

Most of the scripts can be executed directly via the terminal.  
Many projects support `-h` or `--help` arguments to display usage instructions.

---

```bash
Hostdiscovery.py -h

```

## Example Uses

```bash

Hostdiscovery.py --type ARP -i 192.168.1.0 -s /24 -c 10 -t 5 -v 


Hostdiscovery.py --type ICMP1Rec -i 192.168.1.1


Hostdiscovery.py--type ICMP4Rec -i 192.168.1.1 -pt TCP -pr 100 -fi 100 -ic 

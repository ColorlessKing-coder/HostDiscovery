import scapy.all as scapy
from rich import print
import argparse
import requests
import time
from time import sleep
import socket
import random
import os



def animated_sky(duration=10, width=40, height=10):
    """Gökyüzü ve yıldız animasyonunu tek bir fonksiyonda çalıştırır."""
    sky = "🌌"  # Gece gökyüzü arka planı
    stars = ["⭐", "🌟", "✨"]  # Yıldızlar
    import time
    import os
    def generate_sky():
        """Rastgele yıldızlar ekleyerek gökyüzünü oluşturur."""
        sky_lines = []
        for _ in range(height):
            line = ''.join(random.choice(stars) if random.random() < 0.2 else '.' for _ in range(width))
            sky_lines.append(line)
        return '\n'.join(sky_lines)

    start_time = time.time()
    while time.time() - start_time < duration:
        os.system('cls' if os.name == 'nt' else 'clear')  # Konsolu temizle
        print("\033[40m")  # Siyah arka plan
        print(generate_sky())  # Yıldızlarla dolu gökyüzü
        print("\033[0m")  # Renk sıfırlama
        time.sleep(0.5)
def play_police_animation():
    # Renkli ASCII karakterler
    blue = "\033[94m"  # Mavi
    red = "\033[91m"   # Kırmızı
    reset = "\033[0m"  # Renk sıfırlama

    # Animasyon kareleri
    frames = [
        "▓▒░░░░░░░░░░░░░░░░░░░░",
        "▓▓▒░░░░░░░░░░░░░░░░░░░",
        "▓▓▓▒░░░░░░░░░░░░░░░░░░",
        "▓▓▓▓▒░░░░░░░░░░░░░░░░░",
        "▓▓▓▓▓▒░░░░░░░░░░░░░░░░",
        "▓▓▓▓▓▓▒░░░░░░░░░░░░░░░",
        "▓▓▓▓▓▓▓▒░░░░░░░░░░░░░░",
        "▓▓▓▓▓▓▓▓▒░░░░░░░░░░░░░",
        "▓▓▓▓▓▓▓▓▓▒░░░░░░░░░░░░",
        "▓▓▓▓▓▓▓▓▓▓▒░░░░░░░░░░░",
        "▓▓▓▓▓▓▓▓▓▓▓▒░░░░░░░░░░",
        "▓▓▓▓▓▓▓▓▓▓▓▓▒░░░░░░░░░",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▒░░░░░░░░",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░░░░░░░",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░░░░░░",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░░░░░",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░░░░",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░░",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒░",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒",
        "▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓",
    ]

    # Ekranı temizleme fonksiyonu
    def clear_console():
        os.system('cls' if os.name == 'nt' else 'clear')

    # Animasyonu oynatma
    for frame in frames:
        clear_console()
        
        # Kırmızı siren solda, mavi siren sağda
        print(" " * 10 + red + frame + reset + " " * 10 + blue + frame + reset)
        
        # ASCII arabalar yan yana
        print("\n" + " " * 6 + red + "    ____          ____    " + reset + "     " + blue + "    ____          ____    " + reset)
        print(" " * 6 + red + "  _/__|__\\____  _/__|__\\____ " + reset + "     " + blue + "  _/__|__\\____  _/__|__\\____ " + reset)
        print(" " * 6 + red + " |  _     _   ||  _     _   |" + reset + "     " + blue + " |  _     _   ||  _     _   |" + reset)
        print(" " * 6 + red + " '-(_)-------(_)-' -(_)-------(_)-" + reset + "     " + blue + " '-(_)-------(_)-' -(_)-------(_)-" + reset)

        time.sleep(0.1)

    # Renkleri değiştirerek ikinci geçiş
    for frame in frames:
        clear_console()
        
        # Mavi siren solda, kırmızı siren sağda
        print(" " * 10 + blue + frame + reset + " " * 10 + red + frame + reset)
        
        # ASCII arabalar yan yana
        print("\n" + " " * 6 + blue + "    ____          ____    " + reset + "     " + red + "    ____          ____    " + reset)
        print(" " * 6 + blue + "  _/__|__\\____  _/__|__\\____ " + reset + "     " + red + "  _/__|__\\____  _/__|__\\____ " + reset)
        print(" " * 6 + blue + " |  _     _   ||  _     _   |" + reset + "     " + red + " |  _     _   ||  _     _   |" + reset)
        print(" " * 6 + blue + " '-(_)-------(_)-' -(_)-------(_)-" + reset + "     " + red + " '-(_)-------(_)-' -(_)-------(_)-" + reset)

        time.sleep(0.1)







def ParserHostDiscovery():
    Parser = argparse.ArgumentParser(description='HostDiscovery')
    Parser.add_argument('--type', dest='type', help='ICMP4Rec, ARP ,ICMP1Rec', choices=['ICMP4Rec', 'ARP' ,'ICMP1Rec'], required=True)
    Parser.add_argument('-s', '--subnet_mask', help='Give Subnet Mask With (/)', dest='subnet_mask', type=str)
    Parser.add_argument('-i', '--ip_address', help='Give IP Address', dest='ip_address', type=str)
    Parser.add_argument('-c', '--count', help='How Many Times Do You Repeat It', dest='count', type=int, default=1)
    Parser.add_argument('-t', '--timeout', default=1, dest='timeout', type=int, help='Give Response Time')
    Parser.add_argument('-v', '--verbose', help='Let\'s See What Happened', dest='verbose', action='store_true')
    Parser.add_argument('-pr', '--port_scan', help='Give Port Range', dest='port_range', type=int, default=None)
    Parser.add_argument('-pt', '--port_scan_type', help='Give the Port Scan Type', dest='port_type', type=str,choices=['TCP','UDP','SYN','ACK','FIN'],default=None)
    #Parser.add_argument('-a', '--attribute', help='This Will Help You About Scanning', default=None, dest='attribute')
    Parser.add_argument('-fi','--fake-ip',help='Scan With Fake İp Give a Random Ip Range',dest='fake_ip',default=None , type=int)
    Parser.add_argument('-ic','--ip_class',help='Please Select İp Class',default=None,dest='ip_class')
    Parser.add_argument('-p','--proxy',help='Chose Spesific your own proxy server or random option',dest='proxy',default=None)
    args = Parser.parse_args()
    return args

args = ParserHostDiscovery()




def proxy_connect(option=None):
    try:
        if option == "random":
            req = requests.get(f'https://www.proxy-list.download/api/v1/get?type=https')
            if req.status_code == 200:
                print("Proxy adreslerine ulaşılıyor...")
                proxy_list = req.text.splitlines()

                # Random bir proxy seçiliyor
                random_proxy_number = random.randint(0, len(proxy_list) - 1)
                selected_proxy = proxy_list[random_proxy_number]
                ip, port = selected_proxy.split(":")
                
                try:
                    print(f"Seçilen random proxy: {ip}:{port}")
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
                        proxy_socket.settimeout(5)  # Zaman aşımı ekleniyor (5 saniye)
                        proxy_socket.connect((ip, int(port)))
                        print("Proxy sunucusuna başarıyla bağlanıldı.")
                except Exception as e:
                    print(f"Random proxyye bağlanırken hata: {e}")
            else:
                print("Proxy listesine erişim sağlanamadı.")
        
        # Eğer kullanıcı belirli bir proxy girerse
        else:
            ip, port = option.split(":")
            try:
                print(f"Belirtilen proxy: {ip}:{port}")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as proxy_socket:
                    proxy_socket.settimeout(5)
                    proxy_socket.connect((ip, int(port)))
                    print("Belirtilen proxy sunucusuna başarıyla bağlanıldı.")
            except Exception as e:
                print(f"Belirtilen proxyye bağlanırken hata: {e}")

    except Exception as e:
        print(f"Genel hata: {e}")

def SiteCheck():
    try:
        Url = requests.get("https://api.macvendors.com/", allow_redirects=True)
        if Url.status_code == 200:
            print(f"{Url.status_code}")   
        else:
            print("I can't reach", Url.status_code)
    except Exception as e:
        print("Error:", e)

def get_mac_vendor(mac_address: str) -> str:
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url)
        sleep(1)
        response.raise_for_status()  # HTTP hataları varsa bir istisna oluşturur
        return response.text
    except requests.exceptions.RequestException:
        return "Error: Unknown Vendor"

def Protocols():
    return [
    {"port": 20, "service": "FTP (Data)"},
    {"port": 21, "service": "FTP (Control)"},
    {"port": 22, "service": "SSH"},
    {"port": 23, "service": "Telnet"},
    {"port": 25, "service": "SMTP"},
    {"port": 53, "service": "DNS"},
    {"port": 67, "service": "DHCP (Server)"},
    {"port": 68, "service": "DHCP (Client)"},
    {"port": 69, "service": "TFTP"},
    {"port": 80, "service": "HTTP"},
    {"port": 110, "service": "POP3"},
    {"port": 119, "service": "NNTP"},
    {"port": 123, "service": "NTP"},
    {"port": 135, "service": "MS RPC"},
    {"port": 137, "service": "NetBIOS (Name Service)"},
    {"port": 138, "service": "NetBIOS (Datagram Service)"},
    {"port": 139, "service": "NetBIOS (Session Service)"},
    {"port": 143, "service": "IMAP"},
    {"port": 161, "service": "SNMP"},
    {"port": 162, "service": "SNMP Trap"},
    {"port": 194, "service": "IRC"},
    {"port": 220, "service": "IMAP3"},
    {"port": 389, "service": "LDAP"},
    {"port": 443, "service": "HTTPS"},
    {"port": 445, "service": "SMB"},
    {"port": 465, "service": "SMTPS"},
    {"port": 514, "service": "Syslog"},
    {"port": 543, "service": "Kerberos"},
    {"port": 554, "service": "RTSP"},
    {"port": 587, "service": "SMTP (Submission)"},
    {"port": 631, "service": "IPP"},
    {"port": 636, "service": "LDAPS"},
    {"port": 993, "service": "IMAPS"},
    {"port": 995, "service": "POP3S"},
    {"port": 1025, "service": "NFS"},
    {"port": 1433, "service": "Microsoft SQL Server"},
    {"port": 1434, "service": "Microsoft SQL Monitor"},
    {"port": 1521, "service": "Oracle"},
    {"port": 1723, "service": "PPTP"},
    {"port": 3306, "service": "MySQL"},
    {"port": 3389, "service": "RDP"},
    {"port": 3689, "service": "DAAP"},
    {"port": 4444, "service": "DD2"},
    {"port": 5432, "service": "PostgreSQL"},
    {"port": 5900, "service": "VNC"},
    {"port": 6000, "service": "X11"},
    {"port": 6660, "service": "IRC"},
    {"port": 6661, "service": "IRC"},
    {"port": 6662, "service": "IRC"},
    {"port": 6663, "service": "IRC"},
    {"port": 6664, "service": "IRC"},
    {"port": 6665, "service": "IRC"},
    {"port": 6666, "service": "IRC"},
    {"port": 7000, "service": "AOL Instant Messenger"},
    {"port": 8000, "service": "HTTP Alternate"},
    {"port": 8080, "service": "HTTP Proxy"},
    {"port": 8443, "service": "HTTPS Alternate"},
    {"port": 8888, "service": "HTTP Alternate"},
    {"port": 9000, "service": "Webmin"},
    {"port": 9100, "service": "Printer"},
    {"port": 9999, "service": "Trojan"},
    {"port": 10000, "service": "Network Data Management Protocol"},
    {"port": 20000, "service": "Webmin"}
]


def ipv4_creator(ip_class=None):
    if ip_class == 'A':
        first_octet = random.randint(1, 127)
        ip = [random.randint(1, 255) for _ in range(3)]
        return f'{first_octet}.' + '.'.join(map(str, ip))
    
    elif ip_class == 'B':
        first_octet = random.randint(128, 191)
        ip = [random.randint(1, 255) for _ in range(3)]
        return f'{first_octet}.' + '.'.join(map(str, ip))
    
    elif ip_class == 'C':
        first_octet = random.randint(192, 223)
        ip = [random.randint(1, 255) for _ in range(3)]
        return f'{first_octet}.' + '.'.join(map(str, ip))

    
    else:
        ip = [random.randint(1, 255) for _ in range(4)]
        return '.'.join(map(str, ip))



def icmp_packet_with_scapy(ip_address,ip_class,data="This World Shall Know Pain"):
    src_ip = ipv4_creator(ip_class)
    packet = scapy.IP(dst=ip_address,src=src_ip)/scapy.ICMP()/data
    scapy.send(packet,verbose=False)
    print("icmp paketi oluşturuldu : ",src_ip ,"->",ip_address)
    

def tcp_packet_with_scapy(ip_address,ip_class):
    Data = "This World Shall Know Pain"
    dst_port = random.randint(1,65535)
    src_port = random.randint(1,65535)
    src_ip = ipv4_creator(ip_class)
    packet = scapy.IP(src=src_ip,dst=ip_address)/scapy.TCP(sport=src_port,dport=dst_port,flags='S')/Data
    scapy.send(packet,verbose=False)
    print("tcp paketi oluşturuldu : ",src_ip ,"->",ip_address, "Mesaj:", Data)



def PortScannerWithUDP(ip_address: str, port: int) -> bool:

 
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.sendto(b'', (ip_address, port))  # Boş bir UDP paketi gönder b''(boş byte anlamına gelir )
        client.settimeout(1)
        try:
            data, _ = client.recvfrom(1024)  # 1024 bayt kadar veri al data,_ ilk bilgiyi al
            return bool(data)
        except socket.error:
            return False
        
def PortScannerWithTCP(ip_address: str, port: int) -> bool:

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(1)  # Bağlantı Zaman Aşımı Süresi
            client.connect((ip_address, port))
            return True
    except (socket.timeout, socket.error):
        return False

def PortScannerWithSYN(ip_address:str , port:int)->bool:
    response = scapy.sr1(scapy.IP(dst=ip_address) / scapy.TCP(dport=port, flags="S"), timeout=2 , verbose=False) 
    try:
        if response and response.haslayer(scapy.TCP):  #bu İfade İle Paket 4. Katmanı İçeriyormu ona Bakar
            tcp_flags = response[scapy.TCP].flags #Eğer TCP Yani 4. Katmanı İçeriyorsa Sadece O Katmanın Cevabını Al 
            if tcp_flags == 0x12 or  tcp_flags == "SA":  # SYN + ACK bayrakları bit maskesi
                return True
            elif tcp_flags == "R":
                return False
    except Exception as e:
        print("Error : " , e)

def PortScannerWithACK(ip_address:str,port:int)->bool:
    response = scapy.sr1(scapy.IP(dst=ip_address) / scapy.TCP(dport=port, flags="A"), timeout=2 , verbose=False)
    try:
        if response and response.haslayer(scapy.TCP):
            tcp_flags = response[scapy.TCP].flags
             # SYN + ACK bayrağı kontrolü
            if tcp_flags == 0x12 or  tcp_flags == "SA":  # SYN + ACK bayrakları bit maskesi
                return True
            
            elif tcp_flags == 0x02 or tcp_flags == "S":
                return True
            
            elif tcp_flags == 0x10 or tcp_flags == "A":
                return True

            elif tcp_flags & 0x14 or  tcp_flags == "R":  # RST bayrağı bit maskesi
                return False
    
    except Exception as e:
        print("Error : " , e)

def PortScannerWithFIN(ip_address:str , port:int)->bool:
    response  = scapy.sr1(scapy.IP(dst=ip_address) / scapy.TCP(dport=port , flags="F"),verbose=False , timeout=2)
    try:
        if response and response.haslayer(scapy.TCP):
            tcp_flags = response[scapy.TCP].flags
            if tcp_flags == "A" or tcp_flags == 0x01:
                return True
            
            elif tcp_flags == 0x14 or  tcp_flags == "R":
                return False
        
        return False
    
    except Exception as e:
        print(f"[bold red ] Error [/bold red], {e} " )
        return False



        

def HostDiscoveryWithIcmpFourPackReceive(ip_address: str, timeout: int, port_range: int , verbose:bool,port_type,fake_ip_range:int,ip_class,proxy):
    print("")
    print("[bold white]Dest Host \t\t\tReply From Host\t\t\tPort Status \t\t\t Protocols[/bold white]")
    print("[bold yellow]--------------------------------------------------------------------------------------------------------------------------[/bold yellow]")

    PortNumbers = []
    ProtocolList = []
    
    
    if proxy is not None:
        if not proxy_connect(proxy):
            print("Proxy bağlantısı başarısız oldu.")
            return



    if fake_ip_range is not None and port_type is not None:
        for y in range(fake_ip_range):
            tcp_packet_with_scapy(ip_address,ip_class,)

    elif fake_ip_range is not None: 
        for y in range(fake_ip_range):
            icmp_packet_with_scapy(ip_address,ip_class)

    
        

    # Port taraması yapılacaksa, portları kontrol et
    if port_range is not None and port_type is not None:
        
        if port_type == "TCP":
            for x in range(1, port_range + 1):
                Ports = PortScannerWithTCP(ip_address, x)
                if Ports:
                    PortNumbers.append(x)
                

        if port_type == "UDP":        
            for x in range(1, port_range + 1):
                Ports = PortScannerWithUDP(ip_address, x)
                if Ports:
                    PortNumbers.append(x)




        if port_type == "SYN":
            for x in range(1, port_range + 1):
                Ports = PortScannerWithSYN(ip_address, x)  # PortScanner fonksiyonunuz burada çalışıyor
                if Ports:
                    PortNumbers.append(x)

        if port_type == "ACK":
            for x in range(1, port_range + 1):
                Ports = PortScannerWithACK(ip_address, x)  # PortScanner fonksiyonunuz burada çalışıyor
                if Ports:
                    PortNumbers.append(x)
        
        if port_type == "FIN":
            for x in range(1, port_range + 1):
                Ports = PortScannerWithFIN(ip_address, x)  # PortScanner fonksiyonunuz burada çalışıyor
                if Ports:
                    PortNumbers.append(x)

    Proto = Protocols()
    for protocol in Proto:
        Port = protocol["port"]
        Service = protocol["service"]
        for y in PortNumbers:
            if y == Port:
                ProtocolList.append(Service)


    # ICMP isteklerini gönder ve yanıtları al
    send_and_receive = scapy.sr(scapy.IP(dst=ip_address) / scapy.ICMP(), timeout=timeout,verbose=verbose)
    answered, unanswered = send_and_receive

    
    # Yanıtlanan paketleri işle
    if answered:
        for snd, rcv in answered:
            # Loopback adresi 127.0.0.1 ise atla
            if rcv.src != '127.0.0.1':
                print(f"{snd.dst} \t\t\t{rcv.src} \t\t\t{list(PortNumbers)} \t\t\t {ProtocolList}")

    # Yanıtlanmayan paketleri işle
    if unanswered:
        for snd in unanswered:
            # Loopback adresi 127.0.0.1 ise atla
            if snd.dst != '127.0.0.1':
                print(f"Host {snd.dst} is unreachable.")

def HosDiscoveryOnePackReceive(ip_address:str, timeout:int ,port_range:int,verbose:bool,port_type,fake_ip_range:int,ip_class,proxy)->None:
    print("")
    print("[bold white]Dest Host \t\t\tReply From Host\t\t\tPort Status \t\t\t Protocols[/bold white]")
    print("[bold yellow]--------------------------------------------------------------------------------------------------------------------------[/bold yellow]")

    PortNumbers = []
    ProtocolList = []
    SourceIp = ""
    DestIP = ""
     
    if proxy is not None:
        if not proxy_connect(proxy):
            print("Proxy bağlantısı başarısız oldu.")
            return
    
    if fake_ip_range is not None and port_type is not None:
        for y in range(fake_ip_range):
            tcp_packet_with_scapy(ip_address,ip_class,)
    

    elif fake_ip_range is not None: 
        for y in range(fake_ip_range):
            icmp_packet_with_scapy(ip_address,ip_class)

    
        

    # Port taraması yapılacaksa, portları kontrol et
    if port_range is not None and port_type is not None:
        
        
 
        if port_type == "TCP":
            for x in range(1, port_range + 1):
                Ports = PortScannerWithTCP(ip_address, x)
                if Ports:
                    PortNumbers.append(x)
                

        
        
        if port_type == "UDP":
            for x in range(1, port_range + 1):
                Ports = PortScannerWithUDP(ip_address, x)
                if Ports:
                    PortNumbers.append(x)





        if port_type == "SYN":
            for x in range(1, port_range + 1):
                Ports = PortScannerWithSYN(ip_address, x)  # PortScanner fonksiyonunuz burada çalışıyor
                if Ports:
                    PortNumbers.append(x)
         
        if port_type == "ACK":
            for x in range(1, port_range + 1):
                Ports = PortScannerWithACK(ip_address, x)  # PortScanner fonksiyonunuz burada çalışıyor
                if Ports:
                    PortNumbers.append(x)
        
        if port_type == "FIN":
            for x in range(1, port_range + 1):
                Ports = PortScannerWithFIN(ip_address, x)  # PortScanner fonksiyonunuz burada çalışıyor
                if Ports:
                    PortNumbers.append(x)


    Proto = Protocols()
    for protocol in Proto:
        Port = protocol["port"]
        Service = protocol["service"]
        for y in PortNumbers:
            if y == Port:
                ProtocolList.append(Service)



    # ICMP paketi gönder ve yanıtı al
    icmp_packet = scapy.sr1(scapy.IP(dst=ip_address) / scapy.ICMP(), timeout=timeout ,verbose=verbose)
    if icmp_packet:
        src = icmp_packet.src
        dst = icmp_packet.dst
        if src != "127.0.0.1":
            SourceIp = src
        if dst != "127.0.0.1":
            DestIP = dst
    else:
        print("Host'a ulaşılamıyor.")

    
    print(f'{SourceIp} \t\t\t {DestIP} \t\t\t {list(PortNumbers)} \t\t\t {list(ProtocolList)}')

def HostDiscoveryWithArp(ip_address: str, subnet_mask: str, count: int, timeout: int, verbose: bool, port_range:int ,port_type,fake_ip_range:int,ip_class,proxy):
    print("")
    print("[bold white]IP\t\tMAC Adresi \t\tMAC Vendor \t\tPort Status \t\t Service Name[/bold white]")
    print("[bold yellow]----------------------------------------------------------------------------------------------------------------[/bold yellow]")
            
    PortNumbers = []
    Mac_Address = []
    Ip_Address = []
    max_ip_count = 0
    best_scan = []
    ProtocolList = []
    
    

    if proxy is not None:
        if not proxy_connect(proxy):
            print("Proxy bağlantısı başarısız oldu.")
            return



    if fake_ip_range is not None and port_type is not None:
        for y in range(fake_ip_range):
            tcp_packet_with_scapy(ip_address,ip_class,)
    

    elif fake_ip_range is not None: 
        for y in range(fake_ip_range):
            icmp_packet_with_scapy(ip_address,ip_class)

        

    if port_range is not None and port_type is not None:
        
        if port_type == "TCP":
            for x in range(1, port_range + 1):
                Ports = PortScannerWithTCP(ip_address, x)
                if Ports:
                    PortNumbers.append(x)
                

        
        
        if port_type == "UDP":             
            for x in range(1, port_range + 1):
                Ports = PortScannerWithUDP(ip_address, x)
                if Ports:
                    PortNumbers.append(x)


        if port_type == "SYN":
            for x in range(1, port_range + 1):
                Ports = PortScannerWithSYN(ip_address, x)  # PortScanner fonksiyonunuz burada çalışıyor
                if Ports:
                    PortNumbers.append(x)

        if port_type == "ACK":
            for x in range(1, port_range + 1):
                Ports = PortScannerWithACK(ip_address, x)  # PortScanner fonksiyonunuz burada çalışıyor
                if Ports:
                    PortNumbers.append(x)

        if port_type == "FIN":
            for x in range(1, port_range + 1):
                Ports = PortScannerWithFIN(ip_address, x)  # PortScanner fonksiyonunuz burada çalışıyor
                if Ports:
                    PortNumbers.append(x)


    Proto = Protocols()
    for protocol in Proto:
        Port = protocol["port"]
        Service = protocol["service"]
        for y in PortNumbers:
            if y == Port:
                ProtocolList.append(Service)

    try:
        for _ in range(count):
            target_ip = f"{ip_address}/{subnet_mask.split('/')[-1]}"
            arp_request = scapy.ARP(pdst=target_ip,op=1)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=verbose)[0]

            if len(answered_list) > max_ip_count:
                max_ip_count = len(answered_list)
                best_scan = answered_list

        if best_scan:
            for element in best_scan:
                GetLoopMac = element[1].hwsrc
                vendor_info = get_mac_vendor(GetLoopMac)
                Mac_Address.append(element[1].hwsrc)
                Ip_Address.append(element[1].psrc)

                if len(vendor_info) < 35:
                    vendor_info = vendor_info.ljust(35)
                print(f'{element[1].psrc} \t{element[1].hwsrc} \t{vendor_info} \t{list(PortNumbers)} \t {list(ProtocolList)}')
        else:
            print("There is no answer here.")
    except Exception as e:
        print(f'[bold red]Error: {e}[/bold red]')





if __name__ == '__main__':
   
    play_police_animation()
    args = ParserHostDiscovery()
    if args.type == 'ARP':
        HostDiscoveryWithArp(args.ip_address , args.subnet_mask , args.count , args.timeout , args.verbose , args.port_range , args.port_type ,args.fake_ip,args.ip_class,args.proxy)
    elif args.type == 'ICMP4Rec':
        HostDiscoveryWithIcmpFourPackReceive(args.ip_address , args.timeout , args.port_range , args.verbose , args.port_type,args.fake_ip,args.ip_class,args.proxy)
    elif args.type == 'ICMP1Rec':
        HosDiscoveryOnePackReceive(args.ip_address , args.timeout , args.port_range , args.verbose , args.port_type,args.fake_ip,args.ip_class,args.proxy)
    else:
        print("Please choose a valid option.")

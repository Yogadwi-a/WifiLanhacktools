# WifiLanhacktools V.1.0.1

Sebuah tool simpel untuk hack jaringan Wi-Fi

Tersedia untuk:
- WiFi password crack 
- ICMP Flood
- DOS Attack

Script tested in:
- Linux
- Windows

NOTE:
[!]Untuk PC dengan OS Windows wajib terlebih dahulu untuk menginstall Python.
[!]Jika anda melakukan DOS Attack dengan OS Windows, maka anda hanya bisa melakukan serangan single attack dan harus terinstall Npcap dan pydivert
[!]Install requirement-nya terlebih dahulu dengan mengetik "pip3 install -r requirements.txt".

Cara pakai:
1. Serangan crack password Wifi
   Serangan ini bertujuan untuk mencocokan password wifi berdasarkan list yang tersedia di wordlist. serangan ini menggunakan metode Brute Force untuk mencocokan password wifi berada di dalam wordlist. Alur program ini pertama-tama ialah men-scan jaringan wifi tersedia dengan menggunakan Library PyWifi. jika sudah maka akan tampil list SSID Wifi untuk menjadi target. Jika sudah memilih target, maka langkah selanjutnya ialah proses cracking dimana password yang tersimpan di pass.txt dicocokan dengan me-looping list password tersebut. jika password cocok, maka akan muncul pesan dan program akan berhenti.
   
   [*]Cara Pakai:
   - Ketik "python run.py --c scan_wifi_lists" untuk scan jaringan Wifi tersedia.
   - Siapkan Password lists berformat .txt untuk mencocokan Password.
   - Untuk melakukan serangan ketik "python run.py --c crack_wifi_password --s [SSID_WIFI] --w [WORDLIST PASSWORD]" (contoh:python run.py --c crack_wifi_password --s "Target Wifi" --w pass.txt)
   - Tunggu sampai selesai.

   [!]Note:
   + Jika SSID memiliki spasi tambahkan huruf petik seperti contoh diatas.
   + Tekan Ctrl + C untuk berhenti.

2. IP Scan dan serangan ICMP Flood
   Serangan ini bertujuan untuk membanjiri target dengan sejumlah paket ICMP untuk menghambat lalu lintas internet dan kinerja device pada target tersebut. Alur program ini pertama-tama penyerang men-scan terlebih dahulu untuk memilih target dengan IP address. cara kerja IP Scan ini ialah menggunakan ping bawaan sistem lalu mencocokan TTL pada Ping tersebut untuk mengklasifikasi OS target. Tidak hanya itu, program IP Scan terdapat Port scan jadi secara otomatis program akan melihat port yang terbuka. Jika sudah menemukan target maka langkah selanjutnya ialah langkah penyerangan. Program ini memanfaatkan protokol ICMP untuk mengganggu sistem dan jaringan target. User menginputkan IP target, loop, dan payload. lalu program berjalan sesuai loop yang ditentukan. Di dalam loop tersebut terdapat program ICMP header lalu dikirim ke target secara berulang-ulang.
   
   [*]Cara Pakai:
   - Ketik "python run.py --c scan_ip --g [IP_GATEWAY/24]" untuk scan IP Address tersedia.
   - Pilih target IP Address untuk menjadi target.
   - Untuk melakukan serangan ketik "python run.py --c icmp_attack --ip [IP_TARGET] --loop [JUMLAH_LOOP] --pay [JUMLAH_PAYLOAD]" (contoh:python run.py --c icmp_attack --ip 192.168.1.10 --loop 10000 --pay 50000)
   - Tunggu sampai selesai.

   [!]Note:
   + Batas maksimum payload ialah 60000.
   + Tekan Ctrl + C untuk berhenti.
  
3. Serangan DOS Attack
   Serangan ini bertujuan untuk mematikan akses internet pada jaringan Wifi. serangan ini mengkombinasikan dengan ARP Spoofing dengan mengelabuhi MAC address supaya device tersebut percaya kepada MAC kita. Program ini dapat berjalan di Linux dan Windows tetapi, Di OS Windows hanya bisa melakukan serangan pada 1 target saja. Cara kerja program ini pertama-tama ialah program akan menjalankan Scan IP untuk mendapatkan target IP. Selanjutnya, program menjalankan ARP Spoofing dengan target yang didapat tadi. Kemudian, program akan menjalankan IP tables (untuk Linux) atau WinDivert (untuk Windows) untuk menghentikan akses internet supaya mereka terputus dari internet walaupun masih tersambung Wi-Fi. Jika anda memakai OS Linux, maka anda dapat melakukan serangan ini dengan mode all yang bertujuan untuk menghentikan semua akses Internet dan mode single untuk menghentikan akses internet ke target IP tersebut.
   
   [*]Cara Pakai:
   [-]Mode All
      - Ketik "python run.py --c dos_attack --g [GATEWAY] --i [INTERFACE] --g [GATEWAY] --i [INTERFACE] --m all --p [IP_3_DIGIT_PERTAMA.255]" (contoh: python run.py --c dos_attack --g 192.168.1.1 --i wlp2s0 --m all --p 192.168.1.255).
   [-]Mode Single
      - Ketik "python run.py --c dos_attack --g [GATEWAY] --i [INTERFACE] --g [GATEWAY] --i [INTERFACE] --m single --ip [IP_TARGET]" (contoh: python run.py --c dos_attack --g 192.168.1.1 --i wlp2s0 --m single --ip 192.168.1.2).

   [!]Note:
   + Jika anda pakai OS Windows, anda hanya bisa mode single
   + Jika anda pakai OS Windows, jangan lupa install pydivert dan Npcap terlebih dahulu
   + Tekan Ctrl + C untuk berhenti.

[!]Peringatan:
Pembuat tools tidak bertanggung jawab jika terjadi apa-apa. Gunakan tools ini dengan hati-hati.
 

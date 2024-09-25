TRICKSTER SEASON 6 WRITEUP

Started With a Port Scan 

**Sudo nmap -sS -Pn -T5 -p- $ip | rustscan --ulimit 5000 -a $ip -- -sC -sV**

![image](https://github.com/user-attachments/assets/f63c71de-024f-419b-91b9-eba7520fe500)

Port TCP 22 --> OpenSSH 8.9p1 OPEN

Port TCP 80 --> apache 2.4.52 OPEN
===============================================================
Left port 22 As BruteForce Won't Be the Way, So Stared Investigating port 80

Added trickster.htb to /etc/hosts

![image](https://github.com/user-attachments/assets/69e68c07-2830-4c6a-967a-c4d7bff0f708)



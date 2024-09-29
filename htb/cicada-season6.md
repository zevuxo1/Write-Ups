RECON
--
Started Of With Doing a Port Scan  
**nmap $ip -p- -T5 -Pn | rustscan --ulimit 5000 $ip -- -sC -sV -Pn**  
This Returned Me 

    |-53/tcp   open  domain        syn-ack Simple DNS Plus
    |-
    |-88/tcp   open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2024-09-29 11:34:33Z)
    |-
    |-135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
    |-
    |-139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
    |-
    |-389/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
    |-ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
    |-Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
    |-Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
    |-Public Key type: rsa
    |-Public Key bits: 2048
    |-Signature Algorithm: sha256WithRSAEncryption
    |-Not valid before: 2024-08-22T20:24:16
    |-Not valid after:  2025-08-22T20:24:16
    |-MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
    |-SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
    | 
    |-ssl-date: TLS randomness does not represent time
    | 
    |-445/tcp  open  microsoft-ds? syn-ack
    |
    |-464/tcp  open  kpasswd5?     syn-ack
    |
    |-593/tcp  open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
    |
    |-636/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
    |-ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
    |-Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
    |-Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
    |-Public Key type: rsa
    |-Public Key bits: 2048
    |-Signature Algorithm: sha256WithRSAEncryption
    |-Not valid before: 2024-08-22T20:24:16
    |-Not valid after:  2025-08-22T20:24:16
    |-MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
    |-SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
    |
    |-ssl-date: TLS randomness does not represent time
    |-3268/tcp open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
    |-ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
    |-Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
    |-Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
    |-Public Key type: rsa
    |-Public Key bits: 2048
    |-Signature Algorithm: sha256WithRSAEncryption
    |-Not valid before: 2024-08-22T20:24:16
    |-Not valid after:  2025-08-22T20:24:16
    |-MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
    |-SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
    |
    |-ssl-date: TLS randomness does not represent time
    |
    |-3269/tcp open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
    |-ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
    |-Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
    |-Issuer: commonName=CICADA-DC-CA/domainComponent=cicada
    |-Public Key type: rsa
    |-Public Key bits: 2048
    |-Signature Algorithm: sha256WithRSAEncryption
    |-Not valid before: 2024-08-22T20:24:16
    |-Not valid after:  2025-08-22T20:24:16
    |-MD5:   9ec5:1a23:40ef:b5b8:3d2c:39d8:447d:db65
    |-SHA-1: 2c93:6d7b:cfd8:11b9:9f71:1a5a:155d:88d3:4a52:157a
    |
    |-ssl-date: TLS randomness does not represent time
    |Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows
    |
    |-Host script results:
    |-p2p-conficker: 
    |---Checking for Conficker.C or higher...
    |---Check 1 (port 43674/tcp): CLEAN (Timeout)
    |---Check 2 (port 14644/tcp): CLEAN (Timeout)
    |---Check 3 (port 62917/udp): CLEAN (Timeout)
    |---Check 4 (port 13628/udp): CLEAN (Timeout)
    |---0/4 checks are positive: Host is CLEAN or ports are blocked
    |-smb2-security-mode: 
    |----3:1:1: 
    |-----Message signing enabled and required
    |-smb2-time: 
    |---date: 2024-09-29T11:35:22
    |---start_date: N/A
    |-clock-skew: 6h59m59s   


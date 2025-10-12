# Advanced Threat Intelligence Reconnaissance Cheatsheet

*Based on the cybrd0ne/cybersec-toolsbox reconnaissance framework*

## Table of Contents
- [Overview](#overview)
- [OSINT Framework & General Tools](#osint-framework--general-tools)
- [Google Fu / Dorks](#google-fu--dorks)
- [Host Information & DNS](#host-information--dns)
- [Email Discovery & Verification](#email-discovery--verification)
- [Username Hunting](#username-hunting)
- [Password & Credential Hunting](#password--credential-hunting)
- [Personal Information Gathering](#personal-information-gathering)
- [Web Reconnaissance](#web-reconnaissance)
  - [General Information](#general-information)
  - [Subdomain Enumeration](#subdomain-enumeration)
  - [Website Technology Discovery](#website-technology-discovery)
- [Image Intelligence](#image-intelligence)
- [File Analysis](#file-analysis)
- [Social Media Intelligence](#social-media-intelligence)
- [Business Intelligence](#business-intelligence)
- [Wireless Network Intelligence](#wireless-network-intelligence)
- [Cloud Infrastructure Reconnaissance](#cloud-infrastructure-reconnaissance)
  - [Azure Active Directory](#azure-active-directory)
  - [AWS & GCP](#aws--gcp)
- [Automation Scripts](#automation-scripts)
- [Legal & Ethical Guidelines](#legal--ethical-guidelines)

---

## Overview

This cheatsheet provides a comprehensive collection of OSINT (Open Source Intelligence) techniques and tools for advanced threat intelligence reconnaissance. It covers both passive and active reconnaissance methods across organizational and technical domains.

### Key Principles
- **Two main facets**: Organizational and technical reconnaissance
- **Gathering methods**: Passive (preferred) and active reconnaissance
- **Legal compliance**: Always ensure proper authorization
- **Documentation**: Maintain detailed records of all activities

---

## OSINT Framework & General Tools

### Core OSINT Frameworks
```bash
# Recon-ng - Modular reconnaissance framework
recon-ng
workspaces create target_company
marketplace install all
modules search

# Maltego - Visual link analysis
# Download from: https://www.maltego.com/
# Community edition available

# SpiderFoot - Automated reconnaissance
spiderfoot -s target.com
```

### Essential Tools
- **Hunch.ly**: https://hunch.ly/ - Case management for investigators
- **OSINT Framework**: https://osintframework.com/ - Comprehensive tool directory

### Search Engines
```bash
# Primary search engines for different regions/purposes
https://www.google.com/          # Global, Western focus
https://www.bing.com/            # Microsoft ecosystem
https://duckduckgo.com/          # Privacy-focused
https://www.baidu.com/           # China-focused
https://yandex.com/              # Russia/Eastern Europe
```

### GitHub Intelligence
```bash
# Search through code repositories
https://github.com/search?type=code

# Advanced GitHub searches
site:github.com "company_name" password
site:github.com "company_name" api_key
site:github.com "company_name" filetype:env
```

### Creating Sockpuppet Accounts
```bash
# Anonymous persona creation guide
https://www.reddit.com/r/OSINT/comments/dp70jr/my_process_for_setting_up_anonymous_sockpuppet/

# Key considerations:
# - Use separate VPN/Tor for each identity
# - Create believable backstory
# - Maintain consistent posting patterns
# - Use different email providers
```

---

## Google Fu / Dorks

### Essential Google Dork Resources
```bash
# Comprehensive Google dork collections
https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06
https://www.exploit-db.com/google-hacking-database
```

### Basic Search Operators
```bash
# Site-specific searches
site:hackdefense.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"

# Exact phrase matching
"search this exact phrase"
"employee handbook" site:target.com

# File type searches
filetype:pdf "confidential"
filetype:xlsx site:target.com
filetype:docx "internal use only"

# URL pattern searches
inurl:admin site:target.com
inurl:login site:target.com
inurl:dashboard site:target.com

# Title searches
intitle:"index of" "parent directory"
intitle:"admin login" site:target.com
allintitle:admin panel login

# Text content searches
intext:"password" filetype:txt
intext:"api key" site:github.com
allintext:username password login
```

### Advanced Dorking Techniques
```bash
# Combining operators for precision
("Index Of" | "[To Parent Directory]") AND "*financ*" filetype:xlsx site:somebank.com

# Date-based searches
after:2020-01-01 before:2023-12-31 site:target.com

# Wildcard searches
"password is *" site:target.com
"api key: *" filetype:json

# Exclusion searches
site:target.com -site:www.target.com
"sensitive" -site:public-docs.target.com

# Number range searches
site:target.com "employee id" 1000..9999
```

---

## Host Information & DNS

### Domain Information Gathering
```bash
# Get IP addresses of domain
dig target.com +short
dig target.com A
dig target.com AAAA
dig target.com MX
dig target.com NS
dig target.com TXT

# Alternative DNS tools
nslookup target.com
host target.com

# DNS enumeration with different servers
dig @8.8.8.8 target.com
dig @1.1.1.1 target.com
dig @208.67.222.222 target.com
```

### WHOIS Information
```bash
# Check domain registration details
whois target.com
whois ip.address.here

# Historical WHOIS data
# Use online services like DomainTools, WhoisXMLAPI
```

### Mail Security Analysis
```bash
# SPF, DKIM, DMARC analysis
# Using spoofcheck tool
git clone https://github.com/a6avind/spoofcheck
cd spoofcheck
./spoofcheck.py target.com

# Manual DNS checks
dig target.com TXT | grep -E "(spf|dmarc)"
dig _dmarc.target.com TXT
dig default._domainkey.target.com TXT
```

---

## Email Discovery & Verification

### Email Discovery Tools
```bash
# theHarvester - Multi-source email gathering
theHarvester -d target.com -b google -l 500
theHarvester -d target.com -b all -l 1000
theHarvester -d target.com -b linkedin,google,bing -l 200

# All available sources
theHarvester -d target.com -b all -f output.html

# Specific sources
theHarvester -d target.com -b google,bing,yahoo,linkedin,dnsdumpster
theHarvester -d target.com -b shodan,censys,virustotal
theHarvester -d target.com -b crtsh,netcraft,threatcrowd
```

### Online Email Discovery Services
```bash
# Hunter.io - Professional email finder
https://hunter.io
# API usage: curl "https://api.hunter.io/v2/domain-search?domain=target.com&api_key=YOUR_KEY"

# RocketReach - contacts search
https://rocketreach.co
```

### Email Verification
```bash
# Online verification services
https://tools.emailhippo.com/
https://email-checker.net/validate

# Command-line verification tools
# Using h8mail for breach checking
h8mail -t target@domain.com
h8mail -t target@domain.com -bc "/path/to/BreachCompilation/" -sk
```

---

## Username Hunting

### Username Search Services
```bash
# Multi-platform username checkers
https://namechk.com/
https://whatsmyname.app/
https://namecheckup.com/
```

### WhatsMyName Tool
```bash
# Installation and usage
git clone https://github.com/WebBreacher/WhatsMyName
cd WhatsMyName
pip3 install -r requirements.txt

# Usage
python3 whatsmyname.py -u target_username
python3 whatsmyname.py -u target_username -s social_networks.json
```

### Sherlock Tool
```bash
# Installation
git clone https://github.com/sherlock-project/sherlock
cd sherlock
pip3 install -r requirements.txt

# Usage
python3 sherlock target_username
python3 sherlock target_username --timeout 10
python3 sherlock target_username --site Instagram
```

---

## Password & Credential Hunting

### Breach Databases
```bash
# Premium services
https://www.dehashed.com/        # Comprehensive breach database
https://leakcheck.io/           # Multi-source breach search
https://snusbase.com/           # High-quality breach data

# Free services
https://haveibeenpwned.com/     # Troy Hunt's service
```

### Breach-Parse Tool
```bash
# Installation
git clone https://github.com/hmaverickadams/breach-parse
cd breach-parse

# Usage - search by domain
./breach-parse.sh @target.com passwords.txt

# Usage - search by username
./breach-parse.sh target_user passwords.txt

# Search in BreachCompilation
./breach-parse.sh @target.com /path/to/BreachCompilation/data passwords.txt
```

### H8mail - Advanced Breach Hunting
```bash
# Installation
pip3 install h8mail

# Basic usage
h8mail -t target@domain.com
h8mail -t target@domain.com,admin@target.com

# With local breach compilation
h8mail -t target@domain.com -bc "/opt/breach-parse/BreachCompilation/" -sk

# With configuration file
h8mail -t target@domain.com -c config.ini

# Generate config template
h8mail --gen-config

# Example config content:
[h8mail]
shodan_key = YOUR_SHODAN_KEY
hunter_key = YOUR_HUNTER_KEY
hibp_key = YOUR_HIBP_KEY
dehashed_key = YOUR_DEHASHED_KEY
snusbase_key = YOUR_SNUSBASE_KEY
```

### Hash Cracking Resources
```bash
# Online hash crackers
https://hashes.org
https://crackstation.net/
https://md5decrypt.net/

# Hash identification
hashid hash_here
hash-identifier
```

### GitHub Credential Searches
```bash
# GitLeaks - Find secrets in git repos
git clone https://github.com/zricethezav/gitleaks
cd gitleaks
./gitleaks --repo-url=https://github.com/target/repository -v

# Advanced GitHub searches
site:github.com "target.com" password
site:github.com "target.com" api_key
site:github.com "target.com" "secret_key"
site:github.com "target.com" filetype:env
```

---

## Personal Information Gathering

### People Search Engines
```bash
# US-focused services
https://www.whitepages.com/
https://www.truepeoplesearch.com/
https://www.fastpeoplesearch.com/
https://www.fastbackgroundcheck.com/
https://www.411.com/
https://www.spokeo.com/
https://thatsthem.com/

# International/General
https://webmii.com/
https://peekyou.com/
```

### Phone Number Intelligence
```bash
# Phone lookup services
https://www.truecaller.com/
https://calleridtest.com/
https://infobel.com/

# PhoneInfoga tool
git clone https://github.com/sundowndev/phoneinfoga
cd phoneinfoga

# Usage
phoneinfoga scan -n +1234567890
phoneinfoga scan -n +1234567890 --scanner all
```

---

## Web Reconnaissance

### General Information
```bash
# Comprehensive domain analysis
https://centralops.net/co/
https://spyonweb.com/
https://dnslytics.com/reverse-ip
https://viewdns.info/
https://www.virustotal.com/

# Change monitoring
https://visualping.io/

# Backlink analysis
http://backlinkwatch.com/index.php
```

### Historical Analysis
```bash
# Wayback Machine
https://web.archive.org/

# Advanced wayback searches
https://web.archive.org/web/*/target.com
https://web.archive.org/web/20200101000000*/target.com

# CDX API for programmatic access
curl "http://web.archive.org/cdx/search/cdx?url=target.com&output=json"
```

### Subdomain Enumeration

#### Active Tools
```bash
# Amass - Comprehensive subdomain enumeration
amass enum -d target.com
amass enum -d target.com -active
amass enum -d target.com -brute
amass enum -d target.com -src
amass enum -d target.com -o results.txt

# Amass with configuration
amass enum -config config.ini -d target.com

# Multiple domains
amass enum -df domains.txt
```

#### Passive Tools
```bash
# Subfinder - Fast passive enumeration
subfinder -d target.com
subfinder -d target.com -o results.txt
subfinder -d target.com -all
subfinder -d target.com -silent

# With API keys
subfinder -d target.com -config config.yaml

# Assetfinder
assetfinder target.com
assetfinder --subs-only target.com
```

#### Additional Subdomain Tools
```bash
# Sublister
python sublister.py -d target.com
python sublister.py -d target.com -b google,yahoo,virustotal

# DNScan
git clone https://github.com/rbsec/dnscan
python3 dnscan.py target.com
python3 dnscan.py -d target.com -w subdomains.txt

# DNSrecon
dnsrecon -d target.com -t std
dnsrecon -d target.com -t brt -D subdomains.txt

# Gobuster DNS
gobuster dns -d target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
gobuster dns -d target.com -w wordlist.txt -t 50
```

#### Certificate Transparency
```bash
# crt.sh - Certificate transparency logs
https://crt.sh/?q=target.com
curl -s "https://crt.sh/?q=target.com&output=json" | jq -r '.[].name_value' | sort -u

# CHAOS - Project Discovery
chaos -d target.com -silent
chaos -d target.com -o results.txt
```

#### Specialized Subdomain Scripts
```bash
# Multi-tool subdomain enumeration
git clone https://github.com/Gr1mmie/sumrecon
cd sumrecon
./sumrecon.sh target.com

# Combined approach script
git clone https://github.com/zyairelai/subsubsui
cd subsubsui
./subsubsui.sh -d target.com
```

### Website Technology Discovery
```bash
# BuiltWith - Online service
https://builtwith.com/target.com

# Wappalyzer browser extension
# Firefox: https://addons.mozilla.org/firefox/addon/wappalyzer/
# Chrome: Available in Chrome Web Store

# WhatWeb - Command line
whatweb target.com
whatweb -v target.com
whatweb --color=never --no-errors -a 3 target.com
```

---

## Image Intelligence

### Reverse Image Searching
```bash
# Primary reverse image search engines
https://images.google.com/        # Upload or drag image
https://yandex.com/images/        # Often finds more results
https://tineye.com/               # Specialized reverse search

# Advanced techniques
- Use cropped versions of images
- Search for different resolutions
- Try black and white versions
```

### EXIF Data Extraction
```bash
# Online EXIF viewers
http://exif.regex.info/exif.cgi

# ExifTool - Command line
exiftool image.jpg
exiftool -all image.jpg
exiftool -GPS:all image.jpg
exiftool -createdate image.jpg

# Batch processing
exiftool -r -ext jpg -GPS:all /path/to/images/

# Remove EXIF data
exiftool -all= image.jpg
```

### Geolocation Techniques
```bash
# GeoGuessr for location training
https://www.geoguessr.com/

# Geolocation guide
https://somerandomstuff1.wordpress.com/2019/02/08/geoguessr-the-top-tips-tricks-and-techniques/

# Key indicators to look for:
- License plates
- Street signs
- Architecture
- Vegetation
- Power lines
- Language on signs
```

---

## File Analysis

### Metadata Analysis Tools
```bash
# PowerMeta - Windows PowerShell
git clone https://github.com/dafthack/PowerMeta
Import-Module PowerMeta.ps1
Invoke-PowerMeta -TargetDomain target.com

# FOCA - Files of interest finder
git clone https://github.com/ElevenPaths/FOCA
# Follow installation instructions for .NET requirements
```

### Document Discovery
```bash
# Google dorks for files
site:target.com filetype:pdf
site:target.com filetype:docx
site:target.com filetype:xlsx
site:target.com filetype:pptx

# Multiple file types
site:target.com (filetype:pdf OR filetype:doc OR filetype:docx)

# Sensitive document keywords
site:target.com filetype:pdf "confidential"
site:target.com filetype:xlsx "budget"
site:target.com filetype:docx "internal"
```

---

## Social Media Intelligence

### Twitter/X Intelligence
```bash
# Advanced Twitter search
https://twitter.com/search-advanced

# Twitter analysis tools
https://socialbearing.com/         # User analysis
https://www.twitonomy.com/         # Timeline analysis
http://sleepingtime.org/           # Sleep pattern analysis
https://mentionmapp.com/           # Mention mapping
https://tweetbeaver.com/           # Various Twitter tools
http://spoonbill.io/               # Profile change tracking
https://tinfoleak.com/             # Twitter intelligence
```

#### Twint - Twitter Intelligence Tool
```bash
# Installation (may require specific Python version)
pip3 install twint

# Basic usage
twint -u target_username
twint -u target_username -s "keyword"
twint -u target_username --since 2020-01-01
twint -u target_username --until 2023-12-31

# Advanced searches
twint -s "target company" --near "New York"
twint -g="40.7589,-73.9851,1km" -s "keyword"

# Output options
twint -u target_username -o output.csv --csv
twint -u target_username -o output.json --json
```

### Facebook Intelligence
```bash
# Facebook search tools
https://sowdust.github.io/fb-search/
https://intelx.io/tools?tab=facebook

# Manual techniques
- Use graph.facebook.com with user IDs
- Search for email addresses in "Find Friends"
- Check mutual friends
- Analyze photo metadata
```

### Instagram Intelligence
```bash
# Instagram analysis tools
https://wopita.com/                              # Profile analysis
https://codeofaninja.com/tools/find-instagram-user-id/  # User ID finder
https://www.instadp.com/                         # Profile picture viewer
https://imginn.com/                              # Instagram viewer

# Manual techniques
- Check tagged locations
- Analyze hashtags used
- Find connected accounts
- Story highlights analysis
```

### LinkedIn Intelligence
```bash
# LinkedIn advanced search
https://www.linkedin.com/search/results/people/

# Search techniques
- Use company names to find employees
- Search by job titles
- Filter by location and industry
- Check mutual connections
- Analyze company pages for org structure

# Tools for LinkedIn
- LinkedIn Sales Navigator (premium)
- PhantomBuster (automation)
- LinkedIn Helper (browser extension)
```

### Additional Social Platforms
```bash
# Snapchat
https://map.snapchat.com          # Snap Map for location intelligence

# Reddit
https://www.reddit.com/search     # Advanced Reddit search
# Use site:reddit.com in Google for better results

# TikTok
# Manual browsing and hashtag analysis
# Use third-party viewers for deleted content
```

---

## Business Intelligence

### Company Information
```bash
# Business registrations
https://opencorporates.com/       # Global corporate database
https://www.aihitdata.com/        # AI-powered business intelligence

# Manual research techniques
- SEC filings (US companies)
- Companies House (UK)
- Local business registries
- Industry reports
- Press releases
```

### Financial Intelligence
```bash
# Public company information
- Annual reports (10-K, 10-Q forms)
- Proxy statements
- Earnings calls transcripts
- Stock exchange filings

# Private company research
- Dun & Bradstreet reports
- Business credit reports
- Industry databases
- Trade publications
```

---

## Wireless Network Intelligence

### Wireless Network Databases
```bash
# WiGLE - Wireless network mapping
https://wigle.net/

# Usage
- Search by BSSID/MAC address
- Geographic location searches
- Historical network data
- Network naming patterns

# Data collection ethics
- Only use publicly available data
- Respect privacy laws
- Do not access networks without permission
```

---

## Cloud Infrastructure Reconnaissance

### General Cloud Detection
```bash
# Check for cloud IP netblocks
# Azure Netblocks
curl -s https://www.microsoft.com/en-us/download/details.aspx?id=56519

# AWS IP ranges
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | jq .

# GCP IP ranges
curl -s https://www.gstatic.com/ipranges/cloud.json | jq .
```

### IP to Cloud Provider Tool
```bash
# ip2provider tool
git clone https://github.com/oldrho/ip2provider
cd ip2provider
cat iplist.txt | python ip2provider.py
```

### Cloud Enumeration
```bash
# cloud_enum - Multi-cloud enumeration
git clone https://github.com/initstring/cloud_enum
cd cloud_enum
python3 cloud_enum.py -k target_keyword

# Multiple keywords
python3 cloud_enum.py -k keyword1,keyword2,keyword3

# Specific cloud providers
python3 cloud_enum.py -k target --disable-aws
python3 cloud_enum.py -k target --disable-azure
python3 cloud_enum.py -k target --disable-gcp
```

### Azure Active Directory

#### Tenant Discovery
```bash
# Check if tenant exists
curl -s "https://login.microsoftonline.com/target.com/v2.0/.well-known/openid-configuration"

# Alternative method
curl -s "https://login.microsoftonline.com/target.com/.well-known/openid-configuration"

# Check federation status
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com&xml=1"
```

#### AADInternals Framework
```bash
# Installation
Install-Module AADInternals -Force
Import-Module AADInternals

# Comprehensive tenant reconnaissance
Invoke-AADIntReconAsOutsider -DomainName target.com

# Get login information
Get-AADIntLoginInformation -UserName randomuser@target.com

# Get tenant ID
Get-AADIntTenantID -Domain target.com

# Get all tenant domains
Get-AADIntTenantDomains -Domain target.com

# Check for Desktop SSO
Get-AADIntDesktopSSO -Domain target.com
```

#### User Enumeration
```bash
# Check if users exist
Invoke-AADIntUserEnumerationAsOutsider -UserName "user@target.com"

# Bulk user enumeration
Get-Content users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Normal

# Different enumeration methods
Get-Content users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Login
Get-Content users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Autologon

# Guest user format
# external.user_gmail.com#EXT#@target.onmicrosoft.com
```

#### Azure Subdomain Enumeration
```bash
# MicroBurst - Azure service enumeration
git clone https://github.com/NetSPI/MicroBurst
Import-Module MicroBurst.psm1

# Enumerate Azure subdomains
Invoke-EnumerateAzureSubDomains -Base target -Verbose

# Enumerate Azure blobs
Invoke-EnumerateAzureBlobs -Base target -OutputFile azureblobs.txt
```

#### Azure Service Detection
```bash
# Common Azure services to check
target.azurewebsites.net          # App Services
target.scm.azurewebsites.net      # App Service Management
target.blob.core.windows.net      # Blob Storage
target.file.core.windows.net      # File Storage
target.queue.core.windows.net     # Queue Storage
target.table.core.windows.net     # Table Storage
target.database.windows.net       # SQL Database
target.redis.cache.windows.net    # Redis Cache
target.vault.azure.net            # Key Vault
target.azureedge.net              # CDN
```

#### Office 365 Detection
```bash
# Check O365 usage
curl -s "https://login.microsoftonline.com/target.com/v2.0/.well-known/openid-configuration"

# Validate with Gmail
# Try to authenticate with company email at gmail
https://accounts.google.com/
```

#### Email Validation Tools
```bash
# Oh365UserFinder
git clone https://github.com/dievus/Oh365UserFinder
python3 oh365userfinder.py -r emails.txt -w valid.txt -t 30

# OneDrive user enumeration
git clone https://github.com/nyxgeek/onedrive_user_enum
python3 onedrive_user_enum.py -u user@target.com
```

### AWS Detection
```bash
# S3 bucket discovery
# Check for resources loaded from S3
# Look for patterns in Burp Suite:
# https://bucketname.s3.amazonaws.com
# https://s3-region.amazonaws.com/bucketname

# Common S3 bucket naming patterns
target-backups
target-logs
target-data
target-dev
target-prod
target-test
```

### Google Workspace Detection
```bash
# Try to authenticate with company email
https://accounts.google.com/

# Look for Google Workspace indicators
dig target.com MX | grep google
dig target.com TXT | grep "google-site-verification"
```

### Box.com Detection
```bash
# Check for Box portals
https://target.account.box.com
https://targetcompany.account.box.com
```

---

## Automation Scripts

### Basic OSINT Automation Script
```bash
#!/bin/bash

domain=$1
RED="\033[1;31m"
RESET="\033[0m"

# Create directory structure
info_path=$domain/info
subdomain_path=$domain/subdomains
screenshot_path=$domain/screenshots

if [ ! -d "$domain" ];then
    mkdir $domain
fi

if [ ! -d "$info_path" ];then
    mkdir $info_path
fi

if [ ! -d "$subdomain_path" ];then
    mkdir $subdomain_path
fi

if [ ! -d "$screenshot_path" ];then
    mkdir $screenshot_path
fi

echo -e "${RED} [+] Checking domain information...${RESET}"
whois $1 > $info_path/whois.txt
dig $1 ANY > $info_path/dns.txt

echo -e "${RED} [+] Launching subfinder...${RESET}"
subfinder -d $domain > $subdomain_path/found.txt

echo -e "${RED} [+] Running assetfinder...${RESET}"
assetfinder $domain | grep $domain >> $subdomain_path/found.txt

echo -e "${RED} [+] Running Amass...${RESET}"
amass enum -d $domain >> $subdomain_path/found.txt

echo -e "${RED} [+] Checking alive subdomains...${RESET}"
cat $subdomain_path/found.txt | grep $domain | sort -u | httprobe -prefer-https | grep https | sed 's/https\?:\/\///' | tee -a $subdomain_path/alive.txt

echo -e "${RED} [+] Taking screenshots...${RESET}"
gowitness file -f $subdomain_path/alive.txt -P $screenshot_path/ --no-http

echo -e "${RED} [+] OSINT gathering complete!${RESET}"
echo -e "${RED} [+] Results saved in $domain/ directory${RESET}"
```

### Advanced Multi-Tool Script
```bash
#!/bin/bash

target=$1
output_dir="osint_$target"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create output directory
mkdir -p $output_dir/{subdomains,emails,social,files,screenshots}

echo -e "${GREEN}[+] Starting comprehensive OSINT for $target${NC}"

# Email harvesting
echo -e "${BLUE}[+] Harvesting emails...${NC}"
theHarvester -d $target -l 500 -b all > $output_dir/emails/harvester_results.txt 2>/dev/null

# Subdomain enumeration
echo -e "${BLUE}[+] Enumerating subdomains...${NC}"
subfinder -d $target -silent > $output_dir/subdomains/subfinder.txt
assetfinder $target > $output_dir/subdomains/assetfinder.txt
amass enum -passive -d $target > $output_dir/subdomains/amass.txt

# Combine and deduplicate subdomains
cat $output_dir/subdomains/*.txt | sort -u > $output_dir/subdomains/all_subdomains.txt

# Check alive subdomains
echo -e "${BLUE}[+] Checking alive subdomains...${NC}"
httprobe < $output_dir/subdomains/all_subdomains.txt > $output_dir/subdomains/alive.txt

# Technology detection
echo -e "${BLUE}[+] Detecting technologies...${NC}"
while read url; do
    echo "=== $url ===" >> $output_dir/tech_stack.txt
    whatweb $url >> $output_dir/tech_stack.txt 2>/dev/null
done < $output_dir/subdomains/alive.txt

# File discovery
echo -e "${BLUE}[+] Discovering files...${NC}"
echo "site:$target filetype:pdf" > $output_dir/files/google_dorks.txt
echo "site:$target filetype:docx" >> $output_dir/files/google_dorks.txt
echo "site:$target filetype:xlsx" >> $output_dir/files/google_dorks.txt

# Screenshots
echo -e "${BLUE}[+] Taking screenshots...${NC}"
gowitness file -f $output_dir/subdomains/alive.txt -P $output_dir/screenshots/ --no-http >/dev/null 2>&1

echo -e "${GREEN}[+] OSINT collection complete! Results in $output_dir/${NC}"
echo -e "${YELLOW}[+] Manual verification recommended for all findings${NC}"
```

---

## Legal & Ethical Guidelines

### Legal Compliance
```bash
# Always ensure you have proper authorization before conducting reconnaissance
# Key legal frameworks to consider:

# United States
- Computer Fraud and Abuse Act (CFAA)
- Electronic Communications Privacy Act (ECPA)
- Stored Communications Act (SCA)

# European Union
- General Data Protection Regulation (GDPR)
- Network and Information Security Directive (NIS)

# International
- Budapest Convention on Cybercrime
- Local privacy and data protection laws
```

### Ethical Guidelines
```bash
# Professional Ethics
1. Obtain written authorization before testing
2. Respect the scope of engagement
3. Protect discovered information
4. Follow responsible disclosure practices
5. Document all activities thoroughly

# Red Team Rules of Engagement
- Define clear boundaries and scope
- Establish communication protocols
- Set data handling procedures
- Plan for incident response
- Maintain chain of custody
```

### Bug Bounty Considerations
```bash
# Before starting bug bounty research:
1. Read and understand the program scope
2. Respect out-of-scope systems
3. Avoid social engineering unless explicitly allowed
4. Don't access sensitive data
5. Report findings promptly and professionally

# Common out-of-scope items:
- Social engineering attacks
- Physical security testing
- Denial of service attacks
- Testing on production systems
- Third-party applications
```

### Data Protection
```bash
# Protecting discovered information:
1. Use encrypted storage for all findings
2. Implement access controls
3. Regular secure deletion of temporary files
4. Avoid storing personal information longer than necessary
5. Follow organization's data retention policies

# Tools for secure data handling:
gpg --cipher-algo AES256 --compress-algo 1 --symmetric file.txt
veracrypt # For encrypted containers
7z a -p -mhe=on archive.7z folder/ # Password-protected archives
```

---

## References & Additional Resources

### Essential OSINT Resources
```bash
# OSINT Framework
https://osintframework.com/

# Awesome OSINT Lists
https://github.com/jivoi/awesome-osint
https://github.com/Ph055a/OSINT_Collection

# Training and Certification
- SANS SEC487: Open-Source Intelligence (OSINT) Gathering and Analysis
- SANS SEC504: Hacker Tools, Techniques, Exploits, and Incident Handling
- Certified Threat Intelligence Analyst (CTIA)
```

### Tool Collections
```bash
# Comprehensive tool repositories
https://github.com/laramies/theHarvester
https://github.com/OWASP/Amass
https://github.com/projectdiscovery/subfinder
https://github.com/lanmaster53/recon-ng
https://github.com/khast3x/h8mail

# Security distributions
- Kali Linux
- Parrot Security OS
- BlackArch Linux
```

### Stay Updated
```bash
# Follow these resources for latest OSINT techniques:
- Twitter: @IntelTechniques, @nixintel, @OSINTCurious
- Reddit: r/OSINT, r/Intelligence
- Blogs: IntelTechniques.com, OSINTCurio.us
- Conferences: OSINT Summit, BSides events
```

---

*This cheatsheet is for educational and authorized security testing purposes only. Always ensure you have proper permission before conducting reconnaissance activities against any target. The authors are not responsible for any misuse of this information.*

**Last Updated**: October 2025  
**Version**: 2.0  
**Source**: Based on cybrd0ne/cybersec-toolsbox with enhancements for 2025

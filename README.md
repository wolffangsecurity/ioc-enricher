# IOC Enricher  
  
Python threat intelligence tool that queries **VirusTotal**, **AbuseIPDB**, and **Shodan** for a given IP address or domain. 
  
---  
## Project Structure  
  
```  
ioc-enricher/  
├── main.py           
├── requirements.txt   
├── Dockerfile        
└── .env.example      
```
## Usage  
  
```  
usage: main.py [-h] [--json FILE] ioc  
  
positional arguments:  
  ioc          IP address or domain name to investigate  
  
options:
  -h, --help   show this help message and exit
  --file FILE  Path to file with one IOC per line
  --json FILE  Export results to this JSON file path
  --silent     Suppress terminal output, useful for bulk scanning or JSON export

```  
  
---  
  
## Output  
  
Each source is displayed in its own panel with relevant enrichment data. Example fields:  
  
- **VirusTotal** — malicious/suspicious engine count, detection rate, ASN, network, flagged engines  
- **AbuseIPDB** — confidence score, total reports, distinct users, ISP, usage type  
- **Shodan** — open ports, CVEs, organization, ISP, ASN, city, hostnames, domains  
  
---  
## API Keys  
  
Register for free API keys before use:  
  
| Service | Registration |  
|---|---|  
| VirusTotal | https://www.virustotal.com/gui/join-us |  
| AbuseIPDB | https://www.abuseipdb.com/register |  
| Shodan |  https://account.shodan.io/register |  
  
---  
  
## Option 1 — Run Locally  
  
### 1. Clone the repo  
  
```bash  
git clone https://github.com/wolffangsecurity/ioc-enricher.git  
cd ioc-enricher  
```  
  
### 2. Install dependencies  
  
```bash  
pip install -r requirements.txt  
```  
  
### 3. Configure API keys  
  
```bash  
cp .env.example .env  
```  
  
Edit `.env` and fill in your keys:  
  
```  
VIRUSTOTAL_API_KEY=your_key_here  
ABUSEIPDB_API_KEY=your_key_here  
SHODAN_API_KEY=your_key_here  
```  
  
### 4. Run  
  
```bash  
python main.py 43.153.34.199  
python main.py typesmbti.com   
python main.py 43.153.34.199 --json report.json  
```

```
╭────────── IOC Enrichment Report ──────────╮
│ IOC:  43.153.34.199                       │
│ Type: IP                                  │
│ Time: 2026-04-04 18:23:59 UTC             │
╰───────────────────────────────────────────╯
╭──────────────────────────────── VirusTotal ────────────────────────────────╮
│                                                                            │
│   Malicious / Suspicious   11 / 4                                          │
│   Total Engines            94                                              │
│   Detection Rate           16.0%                                           │
│   Reputation               -1                                              │
│   ASN                      132203 (Tencent Building, Kejizhongyi Avenue)   │
│   Country                  US / NA                                         │
│   Network                  43.153.0.0/16                                   │
│   Last Analysis            2026-04-04 04:57 UTC                            │
│   Community Votes          malicious: 1  harmless: 0                       │
│   Tags                     None                                            │
│   Flagged By               ADMINUSLabs (malicious)                         │
│                            Criminal IP (malicious)                         │
│                            alphaMountain.ai (suspicious)                   │
│                            AlphaSOC (suspicious)                           │
│                            Cluster25 (malicious)                           │
│                            CRDF (malicious)                                │
│                            Cyble (malicious)                               │
│                            CyRadar (malicious)                             │
│                            Fortinet (malware)                              │
│                            GreyNoise (suspicious)                          │
│                                                                            │
╰────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────── AbuseIPDB ────────────────────────────────╮
│                                                                           │
│   Confidence Score   100%                                                 │
│   Total Reports      1796                                                 │
│   Distinct Users     233                                                  │
│   Last Reported      2026-04-04T18:00:16+00:00                            │
│   Country            US                                                   │
│   ISP                Asia Pacific Network Information Center, Pty. Ltd.   │
│   Domain Name        apnic.net                                            │
│   Usage Type         Data Center/Web Hosting/Transit                      │
│   Tor Exit Node      No                                                   │
│                                                                           │
╰───────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────────────────────────────────── Shodan ──────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                                                                                                    │
│   Organization   Asia Pacific Network Information Center, Pty. Ltd.                                                                                                                │
│   ISP            Tencent Building, Kejizhongyi Avenue                                                                                                                              │
│   ASN            AS132203                                                                                                                                                          │
│   Country        United States                                                                                                                                                     │
│   City           Santa Clara                                                                                                                                                       │
│   Hostnames      www.typesmbti.com, typesmbti.com                                                                                                                                  │
│   Domains        typesmbti.com                                                                                                                                                     │
│   Open Ports     80, 443, 22, 9527                                                                                                                                                 │
│   CVEs Found     10: CVE-2008-3844, CVE-2025-26465, CVE-2023-51767, CVE-2023-48795, CVE-2023-38408, CVE-2007-2768, CVE-2025-32728, CVE-2023-51384, CVE-2023-51385, CVE-2024-6387   │
│   Tags           None                                                                                                                                                              │
│                                                                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

```
  
---  
  
## Option 2 — Docker  
  
### 1. Clone the repo  
  
```bash  
git clone https://github.com/wolffangsecurity/ioc-enricher.git  
cd ioc-enricher  
```  
  
### 2. Configure API keys  
  
```bash  
cp .env.example .env  
```  
  
Edit `.env` and fill in your keys:  
  
```  
VIRUSTOTAL_API_KEY=your_key_here  
ABUSEIPDB_API_KEY=your_key_here  
SHODAN_API_KEY=your_key_here  
```  
  
### 3. Build the image  
  
```bash  
docker build -t ioc-enricher .  
```  
  
### 4. Run  
  
```bash  
docker run --rm --env-file .env ioc-enricher 43.153.34.199  
```  
  
> **Note:** Always run from the directory containing your `.env` file. API keys are passed at runtime and are never baked into the image.  
  
### With JSON export  
  
```bash  
docker run --rm --env-file .env \  
  -v $(pwd)/output:/output \  
  ioc-enricher 43.153.34.199 --json /output/report.json  
```  
  
---  
  

  

  


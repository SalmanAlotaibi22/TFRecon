# ⚡ TFRecon

TFRecon is a lightweight reconnaissance tool written in Python that combines:

- 🔍 Subdomain discovery  
- 🌐 DNS resolution  
- 🚪 Port scanning  
- 🧠 Service & version detection  

---

## 🚀 Features

- Subdomain enumeration using crt.sh
- Fast multi-threaded port scanning
- Service detection with basic version grabbing
- Clean and simple CLI interface
- Save results to file

---

## 🛠 Installation

### 1. Clone the repository

```bash
git clone https://github.com/SalmanAlotaibi22/TFRecon.git
cd TFRecon
```

---

### 2. Install dependencies

```bash
pip install requests
```

---

### 3. Run the tool

```bash
python tfrecon.py -h
```

---

## 📌 Usage

TFRecon has 3 main modes:

| Mode  | Description |
|------|------------|
| enum | Subdomain enumeration |
| scan | Port scanning |
| full | Full recon (subdomains + port scan) |

---

## 🔎 Subdomain Enumeration

```bash
python tfrecon.py enum -d example.com
```

Skip DNS resolving:

```bash
python tfrecon.py enum -d example.com --no-resolve
```

Save output:

```bash
python tfrecon.py enum -d example.com -o subs.txt
```

---

## 🚪 Port Scanning

Scan common ports:

```bash
python tfrecon.py scan -T example.com --top
```

Scan specific ports:

```bash
python tfrecon.py scan -T example.com -p 80,443,8080
```

Scan port range:

```bash
python tfrecon.py scan -T example.com -p 1-1000
```

---

## ⚔️ Full Recon (Recommended)

Enumerate subdomains and scan them:

```bash
python tfrecon.py full -d example.com --top
```

---

## 💾 Save Results

```bash
python tfrecon.py full -d example.com --top -o results.txt
```

---

## 🧪 Example Output

```bash
[*] Scanning target: example.com

[+] Port 80    open   Service: http | Apache/2.4.41
[+] Port 443   open   Service: https | nginx/1.18.0
[+] Port 22    open   Service: ssh | OpenSSH_7.9
```

---

## ⚙️ Requirements

- Python 3.8+
- requests

---

## ⚠️ Disclaimer

This tool is intended for educational and authorized security testing purposes only.

You are responsible for how you use it.

TFRecon

TFRecon is a lightweight reconnaissance tool written in Python that combines:

Subdomain discovery

DNS resolution

Port scanning

Service and basic version detection

📦 Installation
1. Clone the repository
git clone https://github.com/YOUR_USERNAME/TFRecon.git
cd TFRecon
2. Install requirements
pip install requests
3. Run the tool
python tfrecon.py -h
⚙️ Usage

TFRecon has 3 main modes:

enum → Subdomain enumeration

scan → Port scanning

full → Full recon (enum + scan)

🔍 1. Subdomain Enumeration

Basic usage:

python tfrecon.py enum -d example.com

Without DNS resolving:

python tfrecon.py enum -d example.com --no-resolve

With custom threads:

python tfrecon.py enum -d example.com -t 50
🌐 2. Port Scanning

Scan common ports:

python tfrecon.py scan -T example.com --top

Scan default ports (1–1024):

python tfrecon.py scan -T example.com

Scan specific ports:

python tfrecon.py scan -T example.com -p 80,443,8080

Scan port range:

python tfrecon.py scan -T example.com -p 1-1000

Adjust threads:

python tfrecon.py scan -T example.com --top -t 200
⚡ 3. Full Recon (Subdomains + Scan)
python tfrecon.py full -d example.com --top

Custom ports:

python tfrecon.py full -d example.com -p 80,443,8080
💾 Save Output

Save results to file:

python tfrecon.py full -d example.com --top -o results.txt
🧠 Example Output
[+] api.example.com        -> 192.168.1.10
[+] Port 80 open           Service: http | nginx/1.18.0
[+] Port 22 open           Service: ssh | OpenSSH_8.2
⚠️ Notes

Version detection is basic and depends on service responses

Some services do not expose version information

Results may vary depending on target configuration

⚖️ Disclaimer

This tool is intended for educational purposes and authorized testing only.
Do not scan or test systems without permission.

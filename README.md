# Host-Header-Injection
Host Header Injection is a web security vulnerability that occurs when an application improperly uses the Host HTTP header without proper validation. Attackers can manipulate this header to:  Poison password reset links  Access internal systems  Perform cache poisoning  Bypass authentication  Conduct phishing attacks
Host Header Injection Scanner

A fast, concurrent security scanner designed to detect Host Header Injection vulnerabilities in web applications. This tool helps security professionals, developers, and penetration testers identify misconfigurations where applications improperly trust HTTP Host headers.

🚨 What is Host Header Injection?
Host Header Injection is a web security vulnerability where attackers manipulate HTTP Host headers to:

Poison password reset links and take over accounts

Access internal systems and bypass security controls

Perform cache poisoning attacks on CDNs and proxies

Conduct phishing attacks by manipulating legitimate sites

Bypass authentication mechanisms

✨ Features
🔍 Comprehensive Testing - Tests multiple headers: Host, X-Forwarded-Host, X-Host, X-Forwarded-Server

⚡ High Performance - Concurrent scanning with configurable thread count

📊 Detailed Reporting - Comprehensive results with evidence and headers

🛡️ Safety First - Warning system for sensitive domains (.gov, .bank, etc.)

📁 Flexible Input - Support for single URLs and bulk file processing

Installation 
Download Tool in zip 
unzip folder then compiled this via this command 
go build -o host-header-checker.exe host-header-checker.go

Run Tool Now 
host-header-checker.exe 

⚠️ Disclaimer
This tool is designed for educational and authorized security testing purposes only. The developers are not responsible for any misuse or damage caused by this program. Always ensure you have proper authorization before scanning any systems.

🛡️ Security Considerations
🔐 Authorized Testing Only - Use only on systems you own or have explicit permission to test

⚠️ Sensitive Domains - Tool warns before scanning .gov, .bank, .mil domains

📋 Compliance - Ensure scanning complies with local laws and regulations

🎯 Responsible Disclosure - Report found vulnerabilities to appropriate parties

🔄 Redirect Control - Option to follow or ignore redirects

🎯 Evidence-Based - Captures proof of vulnerability with response analysis

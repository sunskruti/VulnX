# 🛡️ VulnX

### Modular Reconnaissance & Vulnerability Scanning Framework

VulnX is a Python-based cybersecurity reconnaissance and vulnerability scanning tool designed to automate multiple stages of security assessment in a structured workflow.

It combines reconnaissance, network scanning, HTTP analysis, technology fingerprinting, vulnerability lookup, and automated reporting into a single modular framework.

> ⚠️ **Disclaimer:** VulnX is intended strictly for educational purposes and authorized security testing. Only scan systems and domains for which you have explicit permission.

---

## 🚀 Features

### 🌐 Subdomain Enumeration

Discover subdomains associated with a target domain using certificate transparency data.

### 🔍 Port Scanning & Banner Grabbing

Identify open ports and collect service information through banner grabbing.

### 🛡️ Security Header Analysis

Analyze HTTP security headers and identify missing or potentially weak security configurations.

### 🔬 Technology Fingerprinting

Detect technologies and components used by a target web application.

### ⚠️ CVE Lookup

Perform vulnerability-related checks using available CVE information to help identify known security risks associated with detected technologies or services.

### 📊 Automated Reporting

Generate structured reports to make reconnaissance and scan results easier to analyze and review.

### 🧩 Modular Architecture

VulnX is designed with separate components for different scanning tasks, making the project easier to maintain, debug, and extend.

---

## 🏗️ Architecture

```text
                    ┌───────────────┐
                    │    Target     │
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │     VulnX     │
                    │ Orchestrator  │
                    └───────┬───────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
  Subdomain Scan       Port Scanner        HTTP Analysis
        │                   │                   │
        ▼                   ▼                   ▼
 Certificate Data     Banner Grabbing    Security Headers
                                                │
                                                ▼
                                      Technology Detection
                                                │
                                                ▼
                                           CVE Lookup
                                                │
                                                ▼
                                         Report Generation
```

---

## 🛠️ Tech Stack

* **Language:** Python
* **Networking:** Socket Programming
* **DNS Analysis:** `dnspython`
* **HTTP Requests:** `requests`
* **Subdomain Enumeration:** Certificate Transparency (`crt.sh`)
* **CLI:** Python argument parsing
* **Concurrency:** Multithreading
* **Vulnerability Intelligence:** Vulners API
* **Reporting:** HTML/PDF Reports

---

## 📂 Project Structure

```text
VulnX/
│
├── core/                 # Core functionality
├── scanner/              # Scanning modules
│
├── main.py               # Main application entry point
├── recursive_scan.py     # Recursive scanning functionality
├── utils.py              # Utility functions
├── report_template.html  # Report template
│
├── README.md
├── LICENSE
└── .gitignore
```

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/sunskruti/VulnX.git
cd VulnX
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

### Standard Scan

Run a complete scan with automatic JSON and HTML report generation:

```bash
python main.py --target example.com
```

### Recursive Subdomain Scan

Perform a recursive scan of discovered subdomains:

```bash
python main.py --target example.com --recursive 1
```

### Resume / Review Previous Scan

Resume or review a previously generated scan using its JSON report:

```bash
python main.py --resume exports/example.com/<timestamp>.json
```

### Manual Scan

Individual modules can also be executed manually when you want more control over the scanning workflow.

```bash
# Run individual scanning modules
python <module>.py --target example.com
```

Manual execution is useful for testing individual components, debugging, and running only the specific reconnaissance or analysis functionality required.

> ⚠️ **Important:** Only scan domains, hosts, and systems that you own or have explicit permission to test.


## 🔄 Workflow

VulnX follows a structured security assessment workflow:

```text
Target
   │
   ▼
Reconnaissance
   │
   ├── Subdomain Discovery
   │
   ▼
Network Analysis
   │
   ├── Port Scanning
   ├── Banner Grabbing
   │
   ▼
Web Analysis
   │
   ├── Security Headers
   ├── Technology Detection
   │
   ▼
Vulnerability Intelligence
   │
   └── CVE Lookup
   │
   ▼
Report Generation
```

---

## 💡 Why VulnX?

During cybersecurity learning and vulnerability assessment, different tools are often used for different stages of reconnaissance.

VulnX was built as an independent project to explore how these stages could be organized into a single Python-based workflow.

The goal was not simply to automate scans, but to understand:

* How reconnaissance tools work internally
* How networking information can be collected programmatically
* How scanning modules can communicate within a larger system
* How multithreading can improve scanning performance
* How security findings can be structured into useful reports

A key design decision was choosing a **modular architecture instead of building one tightly coupled scanner**, allowing individual components to be improved independently.

---

## 🧠 Key Engineering Challenges

### Modularity vs. All-in-One Automation

One of the major design decisions was choosing between building a completely linear, tightly coupled scanning pipeline or separating functionality into independent modules.

The modular approach was selected because it improves:

* Maintainability
* Debugging
* Extensibility
* Independent feature development

This allows VulnX to evolve as additional reconnaissance and analysis modules are introduced.

---

## 🔮 Future Improvements

Planned improvements include:

* [ ] Additional reconnaissance modules
* [ ] Improved technology fingerprinting
* [ ] Enhanced vulnerability correlation
* [ ] Better scan result visualization
* [ ] Configurable scanning workflows
* [ ] Improved reporting and result prioritization
* [ ] Additional performance optimizations
* [ ] Expanded plugin architecture

---

## 🤝 Contributing

Contributions, suggestions, and improvements are welcome.

If you would like to contribute:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 📜 License

This project is licensed under the **MIT License**.

---

## 👩‍💻 Author

**Sanskruti Mahaveer Shetti**

* GitHub: [@sunskruti](https://github.com/sunskruti)
* IIT Patna | Metallurgical & Materials Engineering
* Interested in Software Development, Cybersecurity, AI, and Robotics

---

### ⭐ If you find this project interesting, consider giving it a star!

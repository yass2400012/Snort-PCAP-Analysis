# Snort IDS PCAP Analysis

## Overview:
This repository documents a hands-on exercise with Snort IDS: creating a custom rule, validating it against live traffic, and performing forensic analysis on a PCAP (Intro_to_IDS.pcap). The goal is to demonstrate detection engineering, PCAP forensics, and Linux operational skills.

---

## Key skills demonstrated

• Snort rule writing and SID management

• Running Snort for live detection and PCAP analysis

• Interpreting Snort alerts (ICMP, SSH) and extracting indicators (source IPs, SIDs)

• Linux command-line for IDS operations and troubleshooting

### 1) Add a Custom Rule
Edit the Snort local rules file (e.g. `/etc/snort/rules/local.rules`) and add:

```snort
alert icmp any any -> 127.0.0.1 any (msg:"Loopback Ping Detected"; sid:10003; rev:1;)
```

Use an appropriate SID range for lab/custom rules to avoid collisions with community rule sets.

### 2) Start Snort for live detection

Launch Snort to monitor the loopback interface and output alerts to the console:

```snort
sudo snort -q -l /var/log/snort -i lo -A console -c /etc/snort/snort.conf
```

## Notes:

• Replace lo if your loopback interface is named differently.

• -q suppresses banner output, -l sets log directory, -A console prints alerts.

### 3) Trigger the detection

Generate ICMP traffic by pinging the loopback address:
```snort
ping -c 4 127.0.0.1
```

Example Snort output (trimmed):

```snort
07/24-10:46:52.401504  [**] [1:10003:1] Loopback Ping Detected [**] {ICMP} 127.0.0.1 -> 127.0.0.1
07/24-10:46:53.406552  [**] [1:10003:1] Loopback Ping Detected [**] {ICMP} 127.0.0.1 -> 127.0.0.1
```

### 4) Forensic exercise — PCAP analysis

Analyze the provided PCAP (Intro_to_IDS.pcap) placed in /etc/snort/:

```snort
cd /etc/snort
sudo snort -q -r Intro_to_IDS.pcap -c /etc/snort/snort.conf -A console
```

## Findings (from PCAP):

• Source IP attempting SSH: 10.11.90.211

• Other detection message present: Ping Detected

• SID for SSH detection rule (as seen in alerts): 1000002


Custom rule

```snort
alert icmp any any -> 127.0.0.1 any (msg:"Loopback Ping Detected"; sid:10003; rev:1;)
```

Start Snort (live monitoring)

```snort
sudo snort -q -l /var/log/snort -i lo -A console -c /etc/snort/snort.conf
```

Run Snort on PCAP
```snort
sudo snort -q -r Intro_to_IDS.pcap -c /etc/snort/snort.conf -A console
```

Generate ICMP traffic
```snort
ping -c 4 127.0.0.1
```

## screenshots:

Place screenshots in screenshots/ and reference inline if desired:

![Snort Rule Created](screenshots/snort_rule_created.png)
![Ping Detected](screenshots/snort_ping_detected.png)
![PCAP Analysis](screenshots/snort_pcap_analysis.png)


## Tools & commands used

• Snort IDS — detection engine and PCAP analysis (-r mode)

• Ubuntu / Linux CLI — editing and executing commands (nano, vim, sudo)

• ping to generate ICMP traffic


## Skills Learned
• writing and validating Snort rules — useful for SOC/IDS positions.

• Threat detection validation: ensuring alerts map correctly to observed network activity.

• Forensic analysis: extracting indicators (source IPs, protocols, SIDs) from PCAPs for incident reports.

• Linux troubleshooting & operational discipline: starting services with correct privileges, managing configuration files.



# Mini SOC Lab – Security Monitoring & Alert Automation

A Mini Security Operations Center (SOC) lab built to monitor Linux security events, detect suspicious activities, and automate security alerts.

## Technologies

- **SIEM:** Wazuh Manager & Agent
- **SOAR:** Shuffle SOAR
- **Operating System:** Ubuntu Linux
- **Monitoring:** Auditd, File Integrity Monitoring (FIM)
- **Threat Intelligence:** VirusTotal API
- **Automation:** Python, Telegram Bot API
- **Virtualization:** VMware

## Architecture

Ubuntu Victim → Wazuh Manager → Shuffle SOAR → Telegram

File Monitoring → VirusTotal API → Shuffle SOAR → Telegram

## Key Features

### 1. Linux Security Monitoring
- 17 custom Wazuh detection rules
- SSH brute-force detection
- Detection of successful SSH login after repeated failures
- Sensitive file monitoring
- Persistence and privilege-related activity detection
- System discovery monitoring

### 2. Security Alert Automation
- Integration between Wazuh and Shuffle SOAR
- Prioritized Telegram security notifications
- Reduced alert noise by filtering low-priority events

### 3. VirusTotal Integration
- Automated monitoring of newly created files
- File submission to VirusTotal for analysis
- Risk classification based on detection results
- Telegram notifications only when malicious or suspicious detections are reported

## Testing

- Validated custom detection rules using Wazuh Logtest
- Tested SSH event correlation with positive and negative scenarios
- Verified Shuffle-to-Telegram alert delivery
- Tested VirusTotal notification filtering using simulated analysis results

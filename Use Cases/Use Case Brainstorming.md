
**Use Case 1: Network Traffic Monitoring**
**Actors**:
-   **Network Administrator**
-   **Suricata IDS/IPS**

*Description**: The Network Administrator uses Suricata to monitor all incoming and outgoing network traffic. Alerts are generated for unusual patterns, such as unexpected spikes in traffic or unusual access attempts.

Misuse Case:
**Actors**:
-   **Malicious Insider**
-   **Suricata IDS/IPS**

*Description**: A malicious insider manipulates or disables Suricata monitoring to cover their tracks while exfiltrating sensitive data or engaging in unauthorized activities.

Nathan claims this one .... will add diagram...

----------
**Use Case 2: Malware Detection**
**Actors**:
-   **Security Analyst**
-   **Suricata IDS/IPS**

*Description**: The Security Analyst relies on Suricata to scan for known malware signatures. When a signature match is found, Suricata automatically blocks the malicious traffic and sends an alert to the Security Analyst.
Misuse Case:
**Actors**:
-   **Cybercriminal**
-   **Suricata IDS/IPS**

*Description**: A cybercriminal employs polymorphic malware that frequently changes its signature, evading detection by Suricata, allowing continued communication with command-and-control servers without triggering alerts.
----------
**Use Case 3: Intrusion Detection**
**Actors**:
-   **System Administrator**
-   **Suricata IDS/IPS**

*Description**: The System Administrator configures Suricata to detect unauthorized access attempts. When a brute-force attack is identified, Suricata alerts the System Administrator to take action, such as blocking the offending IP address.
Misuse Case:

**Actors**:
-   **Attacker**
-   **Suricata IDS/IPS**

*Description**: An attacker uses stealth techniques (e.g., slow-rate or fragmented attacks) to bypass Suricata's intrusion detection capabilities, gaining unauthorized access to network resources without being detected.
----------
**Use Case 4: Data Loss Prevention**
**Actors**:
-   **Compliance Officer**
-   **Suricata IDS/IPS**

*Description**: The Compliance Officer uses Suricata to monitor outgoing traffic for sensitive data. Suricata alerts the Compliance Officer when it detects potential data exfiltration, allowing them to investigate and respond accordingly.
Misuse Case:
**Actors**:
-   **Employee with Malicious Intent**
-   **Suricata IDS/IPS**

*Description**: An employee deliberately obfuscates sensitive data (e.g., through encryption or steganography) to evade Suricata's data loss prevention mechanisms, successfully exfiltrating data without triggering alerts.

Shane claims #4.

----------
**Use Case 5: Protocol Analysis**
**Actors**:
-   **Network Security Engineer**
-   **Suricata IDS/IPS**

*Description**: The Network Security Engineer employs Suricata to analyze specific protocols, like DNS. Suricata flags unusual DNS queries, helping the engineer investigate potential security issues like DNS tunneling.

Misuse Case:
**Actors**:
-   **Attacker**
-   **Suricata IDS/IPS**

*Description**: An attacker exploits vulnerabilities in less-monitored protocols, such as FTP or SNMP, which Suricata is not configured to analyze rigorously, facilitating unauthorized access or data manipulation.
----------
**Use Case 6: Integration with SIEM**
**Actors**:
-   **Security Operations Center (SOC) Team**
-   **Suricata IDS/IPS**
-   **SIEM System**

*Description**: The SOC Team integrates Suricata logs into a SIEM system. The SIEM correlates events from Suricata with other data sources, enhancing threat detection capabilities and providing a centralized view of security events.
Misuse Case:
**Actors**:
-   **Malicious Actor**
-   **Suricata IDS/IPS**
-   **SIEM System**

*Description**: A malicious actor sends false positives or misleading data to the SIEM system from Suricata, creating confusion for the SOC Team and obscuring real security threats.
----------
**Use Case 7: Threat Hunting**
**Actors**:
-   **Threat Hunter**
-   **Suricata IDS/IPS**

*Description**: The Threat Hunter utilizes Suricata's logs and alerts to proactively search for indicators of compromise within the network. They analyze traffic patterns and suspicious activities to uncover potential threats before they escalate.
Misuse Case:
**Actors**:
-   **Adversary**
-   **Suricata IDS/IPS**

*Description**: An adversary anticipates the threat-hunting techniques used by security teams and employs tactics to mimic legitimate user behavior, avoiding detection by Suricata and remaining undetected in the network.

**Use Case 8: Virtual Machine Traffic Monitoring**
**Actors:**
-    Network Administrator
-    Suricata IDS/IPS
*Description**: Suricata's monitoring feature scrutinizes traffic between different virtual machines and logs any anomalies. The Network Adminstrator is notified of the anomalies and inspects Suricata's logs to confirm the suspicious activity or clear the report of any suspicious activity.

**Misuse Case:** 
**Actors:**
-    Malicious Actor
-    Suricata IDS/IPS
*Description**: A malicious actor studies the IDS/IPS methods of Suricata to gain an understanding of how the features work and what activity generates a reportable anomaly. The malicious actor then uses this knowledge to fine tune their attack vectors, being careful to not execute attack methods nor move laterally between virtual machines in such a manner that would trigger an alert from Suricata.

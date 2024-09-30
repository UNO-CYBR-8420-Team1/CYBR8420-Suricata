
# Requirements for Software Security Engineering
## Potential Use/Misuse Case Ideas (Refine Once Finalized)
- Nathan Stechschulte
- Benjamin Bauwens
- Shane Ellis
- Grace Evah Nzoughe
- Matthew Popelka
## Part 1
### Use/Misuse Case 1: Intrusion Detection System with DDoS
- Diagram
- Written Summary
### Use/Misuse Case 2: User Authentication and Access Control
- Diagram
- Written Summary
### Use/Misuse Case 3: Intrusion Preventing System
- Diagram
- Written Summary
### Use/Misuse Case 4: Log Analysis and Manipulation
![Diagram](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Use%20Cases/UseCase1-Log-Analysis-And-Manipulation.drawio.png)
**Description:** The Network Administrator uses Suricata to monitor all incoming and outgoing network traffic. Alerts are generated for unusual patterns, such as unexpected spikes in traffic or unusual access attempts. This lets the Network Admin identify potential security breaches for investigation. 
**Misuse Case Description:** A malicious hacker gains access to the network. Instead of targeting the highly confidential files for medical records, he manipulates the logging files of Suricata by overwriting them  to hide his tracks from Suricata monitoring to cover their tracks while exfiltrating sensitive data or engaging in unauthorized activities. This bypasses any tampering with the alarm definitions or overloading the system with a denial of service attack. The reason the hacker wants to manipulate the logs is to prevent getting caught. 

The real focus here is on the manipulation of the source logs itself and how that can impact the downstream alerting process - making that whole feature and the feature that rely on them useless. The manipulation can hide his actions in the most simple form, or cause "wild goose chases" by just changing the details. Since the software is open-source, if an unauthorized individual got access to the log files themselves they would know where to find them and manipulate them. 

Outside Suricata, some good data protection practices such as the [3-2-1 backup strategy](https://www.backblaze.com/blog/the-3-2-1-backup-strategy/) to replicate the logs for security practices would help defend against this attack (of course, pending implementation). Further more, adding a layer of automatic log comparison to detect log tampering would help not just prevent this, but identify it.  

### Use/Misuse Case 5:
- Diagram
- Written Summary
### Internal Task Assignments and Collaborations
#### [GITHUB Project Board Link](https://github.com/orgs/UNO-CYBR-8420-Team1/projects/1/views/2)
#### Individual Contributions
Here's how we split the responsibilities to create initial drafts:
- GITHUB Project: Nathan had created this already, Shane helped flush out our activities and assign them out
- Use Cases: The entire team contributed to the Use Case Brainstorm document to gather ideas, we then identified our five and split them up and reviewed as follows:
-- Use/Misuse Case 1: Anomaly Detection and Mitigation with DDoS: Ben
-- Use/Misuse Case 2: User Authentication and Access Control: Matt
-- Use/Misuse Case 3: Intrusion Preventing System: Shane
-- Use/Misuse Case 4: Log Analysis and Manipulation: Nathan
-- Use/Misuse Case 5: TBD: Grace
- An AI prompt our team used to improve usecase and misuce case: PROVIDE EXAMPLE SCREENSHOT OF CASE THAT HELPED
- Combining Document: 
- 
#### Team Reflection

The biggest issue we had was getting familiar with Suricata and being aware with it's functionality to come up with use and misuse cases that didn't overlap. We also struggled to understand the difference between a "feature" and an "activity". 

Surprisingly one unexpected issue came when one of our team members used a MAC OS to commit a file to our GITHUB repo that broke anyone else with Windows (because he used invalid characters in the filename). We took advantage of the GIT project "issue" feature to report this and of course discord. It was a learning expierence for everyone, as we normally don't think too much about the other environments others work in and the limitation as a result. 

We did a much better job this time staying pro-active and trying to get ahead of our commitments. We were all able to meet now that we had some times figured out to meet and got more comfortable disussing with each other. Initially there was some confusion on keeping up with commits when working on the project to stay within github vs utilizing OneDrive as a team and then having a designated contributor commit the teams total commits to the repository. We did not see that explict requirement that activity would be monitored for the proposal phase so we used OneDrive to put together the documentation, review each other's work and iterate on the commitments. This time we went forth with understanding that commits need to be applied to the github repository to show full team participation publicly since OneDrive didn't display that which inevitably would push contributors to be more active and not have a single documentor.



## Part 2 - Review of Suricata Project Documentation for Security-Related Configuration and Installation Issues

To review Suricata's security-related documentation, we looked at the project's official documentation for installation and configuration, particularly focusing on sections related to security. Here's a summary of our observations, along with suggestions for improvement:

## 1. Security in Installation and Setup
Suricata’s installation documentation provides detailed instructions on how to install the software on different platforms, but security-related best practices during installation, such as setting up secure user permissions or guidelines for minimizing security risks, are not as prominently featured. For example, running Suricata as a non-root user is crucial for limiting potential damage from an exploit. However, this recommendation is not emphasized. It would be helpful if this section included more specific security tips for installation, such as setting the right access controls and preventing privilege escalation.

- **Suricata Installation Guide:** [Suricata's Installation Documentation](https://suricata.readthedocs.io/en/latest/install.html)

## 2. **Configuration Best Practices**
Suricata's configuration guide gives a lot of useful tips, especially for performance tuning and making the most out of system resources. It covers things like adjusting thread counts, setting the right buffer sizes, and tweaking detection engines based on network traffic. For example, setting up multi-threading helps Suricata manage high-speed networks better by spreading the workload across multiple CPU cores, which can seriously boost performance in healthcare environments with a lot of patient data being processed.

The documentation also talks about balancing detection accuracy with performance by changing how deep Suricata inspects packets, customizing rule sets for specific needs, and using tools like AF_PACKET or Netmap for faster packet processing. While this tuning is key for real-world use, adding more security-focused advice would make the guide even better.

For instance, it could include steps for securing configuration files to stop tampering, using guidelines that fit specific healthcare environments for protecting file access, and using secure protocols (like TLS) for remote management of medical data. Also, adding tips on securing Suricata's management interfaces and applying least-privilege access models for critical healthcare functions would help improve security in actual operational settings.

- **Suricata Configuration Guide:** [Suricata's Configuration Documentation](https://suricata.readthedocs.io/en/latest/configuration/index.html)

## 3. **Logging and Alerts**

Suricata offers extensive logging and alert options, which are highly customizable to adapt to different operational environments. While much of the focus in the documentation is on optimizing logging for performance (ex: reducing logging overhead in high-traffic networks), there is an opportunity to improve security by focusing on logging integrity and tamper-proof mechanisms.

In a healthcare environment, where sensitive data such as patient records and prescriptions are being monitored, ensuring that logs remain intact and free from tampering is critical. For instance, attackers targeting the hospital infrastructure could attempt to modify or delete logs to hide their malicious activities. To safeguard against such threats, Suricata’s documentation could include ways to enable log encryption. Encrypting logs would ensure that even if an unauthorized user gains access, they would be unable to manipulate or alter the logged data without detection.

Moreover, the documentation could benefit from instructions on implementing **append-only filesystems** for log storage. This would prevent logs from being modified or deleted after they are written, providing an additional layer of security. In the context of a hospital, this would be essential for maintaining accurate audit trails in case of an attack on medical infrastructure, such as attempts to manipulate patient records or bypass the intrusion detection system. For example, a **HIPAA-compliant logging configuration** could ensure that any suspicious network activity, such as attempts to access sensitive patient data, are logged and protected, providing forensic evidence for investigation and auditing purposes.

Suricata could aslo encourage the use of **digital signatures** for logs, which would allow administrators in a hospital's Security Operations Center (SOC) to verify the integrity of the log files. If logs are altered in any way, the signature would be invalidated, providing an immediate alert to potential tampering.

By enhancing logging integrity, Suricata would not only ensure the performance and reliability of its alerting mechanism but also provide robust protection for mission-critical environments like healthcare.

- **Suricata Logging Guide:** [Suricata's Logging Documentation](https://suricata.readthedocs.io/en/latest/output/index.html)

#### 4. **Rule Management**

Suricata uses rule sets to detect network threats, suspicious activity, and unusual behavior within a monitored environment. These rule sets are key to how the system spots and responds to potential threats. In a healthcare or hospital setting, where sensitive patient data, medical devices, and important systems like electronic health records (EHR) are at risk, keeping these rule sets secure is really important.

Suricata's documentation explains how to install and update rule sets, but it could use some improvements on how to protect access to these files and verify their integrity during updates. In a hospital, for example, an attacker might try to manipulate rules to cover their tracks, bypass detection, or trigger false alarms to overwhelm security teams. They might alter the rules to avoid getting caught while stealing patient records, or a more advanced attacker could disable intrusion detection to target critical hospital systems like networked medical devices.

To prevent these types of attacks, the hospital's Security Operations Center (SOC) should implement some key security steps for managing rule sets:

- **Access Controls**: Only trusted staff, like senior network security engineers or administrators, should be able to modify the rule sets in Suricata. Role-based access controls (RBAC) within the hospital’s infrastructure can make sure that only authorized people can make changes to the rules.

- **Rule Integrity Verification**: When updating rule sets, especially from outside sources like the Emerging Threats ruleset, it's important to check that the rules haven’t been tampered with. This can be done by verifying digital signatures or hashes before deploying them. For instance, if an attacker modifies rules during the update process, this step would catch those changes and stop the altered rules from being used.

- **Secure Rule Distribution**: In big hospital networks with many Suricata deployments, it's important to make sure rule sets are shared securely. Using encrypted file transfers can prevent attackers from intercepting or changing the rules while they're being sent across different departments.

- **Audit Trails and Alerts for Rule Changes**: Suricata’s rule management should be connected to the hospital’s logging and alerting system. If someone makes unauthorized or unexpected changes to the rule sets, it should trigger alerts so the SOC team can investigate. This is especially important in a healthcare setting, where altered rules could allow attackers to avoid detection and access sensitive data like patient records or gain control over connected medical devices.

By adding these security measures into Suricata's rule management, hospitals can better protect against attacks and insider threats, keeping critical healthcare systems and patient information safe from tampering.

- **Suricata Rule Management Guide:** [Suricata's Rule Management Documentation](https://suricata.readthedocs.io/en/latest/rules/index.html)

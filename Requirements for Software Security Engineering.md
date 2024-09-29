# Requirements for Software Security Engineering
## Potential Use/Misuse Case Ideas (Refine Once Finalized)
- Nathan Stechschulte
- Benjamin Bauwens
- Shane Ellis
- Grace Evah Nzoughe
- Matthew Popelka
## Part 1
### Use/Misuse Case 1:
### Use/Misuse Case 2:
### Use/Misuse Case 3:
### Use/Misuse Case 4:
### Use/Misuse Case 5:
### Internal Task Assignments and Collaborations
#### Project Board
[CYBR8420-Suricata](https://github.com/orgs/UNO-CYBR-8420-Team1/projects/1/views/2)
#### Individual Contributions
#### Team Reflection
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




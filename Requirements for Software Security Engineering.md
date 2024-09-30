
# Requirements for Software Security Engineering
## Part 1
### Use/Misuse Case 1: Anomaly Detection and Mitigation with DDoS
![Diagram](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Use%20Cases/UseMisuseFinal%231.drawio.png)
**Description:** The Security Analyst at the hospital utilizes Suricata for anomaly detection and mitigation against threats, in this case above it's against Distributed Denial of Service (DDOS) attack. The Suricata system actively runs IDS,IPS, and NMS to follow the imputed rules that were configured to find alerts. These alerts are then logged and checked by the security analyst. These logs however are susceptible to being attacked. Hospitals are known for their critical devices and data including Personable Identifiable Information or (PII) and health records. The hospital security analysts practice anomaly detection and mitigation efforts to proactively, reactively, and retroactively stop a threat in its tracks. The analyst has the ability to mitigate these troubles through traffic scrubbing, SIEM integration, load balancing, and reviewing logs. These efforts are utilized to stop a Distributed Denial of Service (DDOS) attack among other attacks.

**Misuse Case Description:** A disgruntled patient that may be upset with the provider or system as a whole causes a Distributed Denial of Service (DDOS) attack that causes legitimate alerts to get missed, system hardware performance issues and alert fatigue due to flood of requests and erroneous data. The patient that is looking to get even in this malicious way results in a compromised system.

Adding traffic scrubbing rules while Suricata is running in inline mode can help intercept and modify traffic to drop malicious traffic before it gets through the system. The logs the system collects can be utilized for further analysis. Security Information and Event Management (SIEM) integration can allow for better tools for analysts to detect and analyze data for a stronger method in staying on top of the latest threats and trends. Lastly, load balancing can help system resources be reallocated or divided up to not overwhelm the system as it experiences these troubles.
### Use/Misuse Case 2: User Authentication and Access Control
![Diagram](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Use%20Cases/Auth-AccessControlUseMisuseCase2.png)
**Description:** The Network Administrator or Security Analyst accesses Suricata to view activity logs and add, remove, or view existing rules for Suricata’s Intruder Detection and Intrusion Prevention Systems (IDS/IPS). Suricata is running on a host system in the hospital’s network. It takes input from users via command line interface (CLI), and it does not have a user authentication page.

**Misuse Case Description:** A Malicious Actor associates to the hospital’s network via an open, unsecured network. Once on the network, the actor traces the data path back to the network’s Suricata instance and determines that no login credentials are required to access Suricata. The actor is also familiar with the proper CLI syntax to add, edit, and remove rules from Suricata. Using this knowledge with the lack of user authentication, the actor successfully accesses Suricata and can change any rules to circumvent Suricata’s intended functionality. From the unintentional standpoint, a tech-savvy client authenticates to the hospital’s internal network and manages to access Suricata. Since Suricata does not have any user authentication practices, the client has immediate access to Suricata and can send inputs to Suricata that adjust IDS/IPS settings.

The issue highlighted here is the lack of user authentication natively provided by Suricata. By itself, Suricata is CLI-based, so no user interface component exists and, therefore, no login screen is present. From the CLI, no user authentication exists. This means that anyone who knows the location of the Suricata instance on a network (or who might stumble upon the location of Suricata) can make changes to Suricata’s rules that govern its network monitoring. 

Adding an authentication mechanism to access Suricata is the most straightforward solution to this issue. One way of doing this is by developing user authentication functionality to Suricata. This could be managed within the Suricata instance, by an authentication server located on the network Suricata protects, or by deploying Suricata within a container and implementing proper security controls to that container. Another solution to enhance access control to Suricata is by properly segmenting and securing guest networks from internal networks. This would prevent a tech-savvy client from randomly discovering the Suricata instance (or other sensitive data) on the internal network.

### Use/Misuse Case 3: Intrusion Preventing System
![Diagram](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Use%20Cases/UseMisuseFinal%233.drawio.png)
**Description:** A network administrator overseeing a healthcare system utilizes Suricata in order to observe and manage activities occurring on the system network. In doing so, the administrator is able to access Suricata's intrusion detection and prevention systems (IDS/IPS). Through accessing said component, IPS rules can be viewed as well as configured to remain vigilant towards threats the administrator anticipates could occur towards the system. In addition, the administrator can view logs and alerts from the IPSto follow system activity. 

**Misuse Case Description:** An outside actor, such as a foreign nation whose goal is to target healthcare infrastructure may seek to to disrupt or damage devices used in healthcare to assist in various treatment processes. To invoke this, the misuser could attain unauthorized access to the IDS and IPS found within Suricata in order to manipulate the system to their will. From this point rules could be altered so as to not prevent intrusions from occurring enabling the misuser to work their way towards greater network access. Once greater network access has been attained the misuser would then have access to logging and alerting mechanisms provided by the IPS which may include network addresses for sensitive medical equipment that is vulnerable to attacks.

Utilizing an audit logging mechanism addresses part of the misuse issue with respect to Suricata's operation as that provides insight into activity from the IPS to prevent potential malicious IPS rule manipulation. Additional mechanisms that could further seek to address the issue include methods of authentication or access roles for further specification as to who may access the system for unauthorized access prevention. Providing stricter security measure on logging and alerting mechanisms could help to prevent misusers from viewing network activity from Suricata.

### Use/Misuse Case 4: Log Analysis and Manipulation
![Diagram](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Use%20Cases/UseCase1-Log-Analysis-And-Manipulation.drawio.png)

**Description:** The Network Administrator uses Suricata to monitor all incoming and outgoing network traffic. Alerts are generated for unusual patterns, such as unexpected spikes in traffic or unusual access attempts. This lets the Network Admin identify potential security breaches for investigation. 

**Misuse Case Description:** A malicious hacker gains access to the network. Instead of targeting the highly confidential files for medical records, he manipulates the logging files of Suricata by overwriting them  to hide his tracks from Suricata monitoring to cover their tracks while exfiltrating sensitive data or engaging in unauthorized activities. This bypasses any tampering with the alarm definitions or overloading the system with a denial of service attack. The reason the hacker wants to manipulate the logs is to prevent getting caught. 

**Extended Thoughts:** The real focus here is on the manipulation of the source logs itself and how that can impact the downstream alerting process - making that whole feature and the feature that rely on them useless. The manipulation can hide his actions in the most simple form, or cause "wild goose chases" by just changing the details. Since the software is open-source, if an unauthorized individual got access to the log files themselves they would know where to find them and manipulate them. 

Outside Suricata, some good data protection practices such as the [3-2-1 backup strategy](https://www.backblaze.com/blog/the-3-2-1-backup-strategy/) to replicate the logs for security practices would help defend against this attack (of course, pending implementation). Further more, adding a layer of automatic log comparison to detect log tampering would help not just prevent this, but identify it.  

### Use/Misuse Case 5: Rule configuration Management
![Diagram](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Use%20Cases/Rule%20management%20modified.drawio.png)
  
**Description:**
In an healthcare environment, insurance fraudsters aim to access sensitive patient records and insurance details to file fraudulent claims or manipulate medical billing for financial gain. The fraudsters target Suricata to reach their goal.

- The hospital's IT security team including the system admin regularly manages Suricata's rule sets to detect potential anomalies in the network, unauthorized access attempts or unusual data flows. This includes installing new rule updates to enhance threat detection and deleting outdated or irrelevant rules.
- To ensure the authenticity of these rule updates, the hospital applies digital signatures. Every rule set update must be verified through this signature to confirm its integrity, preventing any tampering with the rule files during transfer or installation.
- Insurance fraudsters, aiming to access patient data, know that tampering with rule updates could allow them to bypass detection. They attempt to intercept the hospital’s network traffic to inject malicious rules during an update process. The goal is to introduce a backdoor that allows them to siphon data or manipulate billing systems without being detected by Suricata.
- In response to this, the IT team strengthens the update process by adding two-factor authentication (2FA) for anyone attempting to modify or update rule sets. This ensures only authorized personnel can implement rule changes.
- The fraudsters, realizing they can’t inject malicious rules due to the new solutions in place, they launch a phishing attack on hospital IT staff, aiming to steal their credentials. By compromising an IT employee’s login, they can bypass 2FA and directly tamper with the rule management system, allowing them to insert their fraudulent rules that avoid detection.
- To combat rule tampering, the hospital IT team uses integrity verification mechanisms, like cryptographic hashes and checksums, to ensure the rules haven’t been altered. Every rule set must pass this verification process before being applied to Suricata.
- After updating and installing new rules, the administrator runs a validation process to ensure Suricata is functioning correctly and detecting threats as expected. This process involves checking network traffic to confirm that the new rules are actively identifying anomalies.
- The attackers attempt a man-in-the-middle (MITM) attack, trying to impersonate the admin to manipulate the outcome of the rule validation. By intercepting the communications, they are trying to bypass the encryption or trick the system into accepting their malicious changes.


  
### Utilization of AI for Improving Use/Misuse Case Diagrams
For utilizing of AI prompting for the purpose of improving of use/misuse case diagrams, a prompt used can be seen below:

```
An actor is associated with the "Access IDS/IPS" use case where IDS an intrusion detection system system and IPS is an intrusion prevention system.
The actor is associated with the "Access IPS Logs" use case which has dependencies with "Access Medical Device Addresses" and "Monitor Medical Device Operational Status" use cases.
The actor is associated with the "Access IPS Alerts" use case which has dependencies with "Access Medical Device Addresses" and "Monitor Medical Device Operational Status" use cases.
The "Access IDS/IPS" use case has dependencies with "View IPS Rules" and "Configure IPS Rules" use cases.
The "Configure IPS Rules" has a dependency with the "View IPS Rules" use case.
```

In order to make use of AI in seeking to improve use/misuse case diagrams, ChatGPT 4o mini was leveraged. The situational context provided for the chat bot for processing use and misuse cases mirrored that of the example included with the instructional material for the assignment. In the case of the prompt provided, the diagram described to the chat bot pertained to our third use/misuse case in which the IPS was examined with an outsider, specified to be a hostile foreign nation, seeking to target and disrupt important medical devices located on a healthcare system on which Suricata is utilized.

The output generated by the chat bot was comprehensive in that it accounted for use cases provided to it through the prompt, likely misuse cases for the initial use cases, and three additional misuse cases and responses that could be developed to fit the diagram at hand. Upon review, the three likely misuse cases outlined by the chat bot were those that were previously recognized in creating the initial diagram in response to the initial use cases: the misuser gaining access to Suricata, changing rules present on the IPS, and accessing IPS logs which was already included through the misuser acquiring network access.

The more interesting component from the output was the proposed remedies to the first three misuse cases it had identified which corresponded to those already covered. Proposed solutions included role-based access and 2FA to solve the unauthorized access to Suricata, audit logging and version control monitoring to solve IPS rule manipulation, and log file encryption and access control lists to solve accessing IPS logs. These observations allowed for the improvement of the use case diagram with the subsequent inclusion of an audit logging use case to account for the misuser attempting to change rules present on the IPS. The other proposed solutions were not included into the diagram as the current support in Suricata is not present or is unclear as of this time, but provide interesting ideas for expansion.

The remaining output generated pertained to the misuse that could occur with the proposed solutions to the initial misuse cases to which a second round of solutions were iterated by the chat bot: security awareness training for misuse cases against role-based access and 2FA, immutable logs for misuse cases against audit logs, and access audits for misuse cases against access control lists. While these were not applied to the diagram for reasons previously mentioned they continue to add to possible outlets for improvement.

### Security Requirements Derived from Misuse Case Analysis
- **Todo:** Build a list of security requirements derived from misuse case analysis. (Compile a list from our respective cases)
  
 Based on our use/misuse case analyses to secure increase Suricata's security requirements, strict **access control** must be enforced, allowing only authorized personnel to modify or update rule files. This should be complemented by **multi-factor authentication (MFA)** for all administrative access to ensure an additional layer of protection against unauthorized logins. To safeguard the integrity of rule updates, **strong cryptographic hashes** must be used for verification, and all rule sets should be **digitally signed** to prevent tampering. Since suricata does not have any **role-based access control (RBAC)**, implementing it ensures that access to critical rule management tasks is restricted based on user roles and privileges, minimizing potential misuse.

 From misuse case #1 We want to prevent a DDOS attack adding rules for traffic scrubbing when in an inline setup to prevent traffic and drop it before it makes it to its intended destination. SIEM integration allows for better analysis of the logs along with trends and latest tools for a more robust system. Additionally Suricata needs to be set up for load balancing which allows resources to be broken up and work more efficiently so the system doesn’t crash.

 From misuse case #4 we should make sure the logging system used is secure from threats, and we could leverage another tool to make backup copies of the logs to help detect manipulation of the logs. Additionally, we could have Suricata be able to parallel stream it's logs to another secure server could help. That way there's no delay between the network activity logs being written and backup being made. This ultimately would help address individuals hijacking and manipulating logs to cover their tracks. 

### Alignment of Security Derived Security Requirements
- **Todo:** Assess the alignment of security requirements derived from misuse case analysis with advertised features of the open-source software. Review OSS project documentation and codebase to support your observations. Provide a summary of your findings, reflecting on the sufficiency of security features offered by the open source project versus those expected by the mis use case analysis.
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
-- Use/Misuse Case 5: Rule Configuration Management: Grace
- An AI prompt our team used to improve usecase and misuce case: 
- Combining Document: Everyone, helping to place portions of the project on where they needed to go such as the diagrams, misuse cases and reasoning.
- 


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


#### Team Reflection

The biggest issue we had was getting familiar with Suricata and being aware with it's functionality to come up with use and misuse cases that didn't overlap. We also struggled to understand the difference between a "feature" and an "activity". 

Surprisingly one unexpected issue came when one of our team members used a MAC OS to commit a file to our GITHUB repo that broke anyone else with Windows (because he used invalid characters in the filename). We took advantage of the GIT project "issue" feature to report this and of course discord. It was a learning expierence for everyone, as we normally don't think too much about the other environments others work in and the limitation as a result. 

We did a much better job this time staying pro-active and trying to get ahead of our commitments. We were all able to meet now that we had some times figured out to meet and got more comfortable disussing with each other. Initially there was some confusion on keeping up with commits when working on the project to stay within github vs utilizing OneDrive as a team and then having a designated contributor commit the teams total commits to the repository. We did not see that explict requirement that activity would be monitored for the proposal phase so we used OneDrive to put together the documentation, review each other's work and iterate on the commitments. This time we went forth with understanding that commits need to be applied to the github repository to show full team participation publicly since OneDrive didn't display that which inevitably would push contributors to be more active and not have a single documentor.

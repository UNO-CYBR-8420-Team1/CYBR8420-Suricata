
# Project Description
Suricata is an open-source NSM program that is managed and maintained by the Open Information Security Foundation (OISF) that features an Intrusion Detection System (IDS) and Intrusion Prevention System (IPS) as the more notable components. This system is advertised both to private and public entities as a means to both actively sniff and avert bad actors while also allowing for users to set custom rules tailored to the needs of the user’s system. In addition to rules created by the user, the system can actively capture network data for logging and assessing anomalies found while utilizing this system. The logs the software captures can then be used to adjust the settings to help create/maintain a more robust system. The peace of mind that comes with this NSM is the backing of an active foundation that will continue to provide support as long as it is around. This OSS continues to run stable with the most recent release on June 27, 2024 with ongoing pre-conference training ([intrusion analysis & threat hunting](https://suricata.io/event/intrusion-analysis-threat-hunting-suricon2024-pre-conference-training/)) found on upcoming events on their website. There are currently 193 contributors with the primary languages being C and Rust. 

# Team Motivation
The core need for integrity of an organization's system isn’t going away and will always be around as long as there are bad actors in the cyberworld. The need for Network Security Monitoring (NSM) helps the organization reinforce their foundation both by allowing proactive and reactive measures. Suricata allows for an additional layer of security awareness to be able to monitor, log, restrict, and alert the organization of their network findings. We believe that of the projects researched this one has stood out to us and is a tool we might be able to better understand and utilize. A couple of members from our group are also in the networking field so an opportunity to dive deeper into an open-source system that could prove to be useful in our everyday job proves to be a great chance to learn more about it. Additionally, as developing individuals in the security space this is a good avenue to contribute to software assurance. 

# Security Background and History

Suricata was created in 2009 by the Open Information Security Foundation (OISF). The project was initiated to create an advanced open-source Intrusion Detection System (IDS) and Intrusion Prevention System (IPS) that could address the increasing complexities of modern network security. Since then, it has evolved significantly to include various features like Deep Packet Inspection (DPI), Network Security Monitoring (NSM), and threat detection capabilities. 

Through the Common Vulnerabilities and Exposure (CVE) website we can see a database list of publicly disclosed vulnerabilities as pertained to Suricata. For instance:  

**CVE-2024-28870** Suricata is a network Intrusion Detection System, Intrusion Prevention System and Network Security Monitoring engine developed by the OISF and the Suricata community. When parsing an overly long SSH banner, Suricata can use excessive CPU resources, as well as cause excessive logging volume in alert records. This issue has been patched in versions 6.0.17 and 7.0.4. https://www.cve.org/CVERecord?id=CVE-2024-28870 

**CVE Impact (2):** This vulnerability could lead to two primary issues: 

*(1) Excessive CPU Usage:* When Suricata encountered a very long SSH banner, it could cause a spike in CPU usage due to the effort required to parse such a large string. This could degrade system performance, making Suricata slow or unresponsive, which is critical in a high-performance security monitoring environment. 

*(2) Excessive Logging Volume:* In addition to performance issues, Suricata would generate excessive logs related to this anomaly, overwhelming the logging system. This could cause storage and log management issues, and even make it harder to spot legitimate security incidents in the sea of generated log entries. 

This is particularly important because an attacker could exploit this vulnerability by sending an **artificially long SSH banner** to a Suricata-monitored system. The issue was addressed and **patched in Suricata versions 6.0.17 and 7.0.4**. 



The [Suricata Documentation](https://docs.suricata.io/en/latest/) site provides in-depth information on features, updates, and protocol parsers. We can find detailed descriptions of security features and system designs. For instance, it seems like they are using a **modular design** for security features to be updated or replaced without affecting the entire system ( Protocol parsers, detection engine, I/O layer, etc. ). These are separated modules that interact with one another. 

One recent feature addition is the EVE JSON output, which provides detailed logs for security events in an easy parsable format. This enhances the visibility and auditability of security events in the network.  

The Suricata project is continuously evolving with regular/recent [security patches and updates](https://suricata.io/category/release/). The development team maintains an active changelog to track all known vulnerabilities, mitigations, and feature upgrades, ensuring that Suricata remains a reliable and secure network monitoring solution. 

# Hypothetical Operational Environment: Healthcare System

For our project we have chosen to use the healthcare system as Suricata hypothetical operational environment which consists of hospitals, clinics, and remote health facilities. The healthcare system relies heavily on interconnected electronic health record (EHR) systems, cloud-based medical applications, and networked medical devices like infusion pumps, patient monitors, and imaging systems to provide critical care to patients. In this environment, Suricata plays a key role in monitoring network traffic, detecting anomalies, and safeguarding sensitive data.

One of the most critical components in this healthcare system is the electronic health record (EHR) system, which stores a vast amount of sensitive patient data, including medical histories, prescriptions, lab results, and personal information. Additionally, various medical devices, such as imaging equipment and heart monitors, are connected to the network, making them potential targets for cyberattacks. Remote access systems for telehealth consultations and patient monitoring further expand the network’s vulnerability, as physicians and healthcare staff need secure ways to access patient data from different locations.

In this environment, security needs are focused on protecting patient data privacy and ensuring compliance with regulations such as HIPAA (Health Insurance Portability and Accountability Act). There is also a need for constant network monitoring to detect unauthorized access or suspicious activities that could compromise patient data or disrupt the hospital's medical devices. Suricata is crucial in identifying and preventing potential intrusions, such as attempts to manipulate patient records, alter prescriptions, or tamper with the hospital's connected medical equipment.

# Perceived Threats by Users
Attackers could try to breach the network with common attacks like:
-   Brute force attacks
-   Buffer overflow
-   Zero days vulnerabilities
-   DoS

Therefore  Suricata users are expecting protection against these **network based attacks**.
-   **Malware infection**: Suricata  is able to detect malware signature via IDS and IPS signatures
-   **Advanced Persistent Threats**: Suricata is expected to recognize patterns of data exfiltration, anomalous behavior, and unauthorized access attempts by attackers who have gained access through phishing or exploiting vulnerabilities.
-   **Man in the middle attack**: Suricata is expected to detect suspicious SSL/TLS certificates or attempts to downgrade secure connections, packet tampering or modification during transit
-   **Data Exfiltration**: Suricata  is able to detect unusual outbound traffic patterns or large data uploads
-   **Vulnerability**: Suricata is able to detect vulnerability scans or reconnaissance attempts by attackers, any outdated or misconfigured services on the network
-   **Web Application Attacks**: Suricata can detect SQL Injection, Cross-Site Scripting (XSS), and Remote File Inclusions

# Suricata Features
-   **Intrusion Detection System (IDS)**: Monitors network traffic for suspicious patterns and generates alerts for potential threats.
-   **Intrusion Prevention System (IPS)**: Actively blocks or prevents malicious traffic based on predefined security rules.
-   **Network Security Monitoring (NSM)**: Provides real-time analysis of network traffic for security insights and anomaly detection.
-   **Deep Packet Inspection (DPI)**: Examines the content of data packets to detect malicious activities at various protocol layers.
-   **Protocol Detection and Parsing**: Identifies and decodes common network protocols (e.g., HTTP, SSH) to detect abnormalities or malicious use.
-   **TLS/SSL Decryption**: Monitors and analyzes encrypted network traffic by decrypting SSL/TLS connections for deeper inspection.
-   **Signature-Based Detection**: Uses signatures to detect known attacks and vulnerabilities in network traffic.
-   **File Extraction and MD5 Hashing**: Extracts files from network traffic and generates hashes for malware analysis and detection.
-   **High Performance Multi-Threading**: Efficiently handles high volumes of traffic using multi-threading for faster and scalable detection.
-   **EVE JSON Output**: Logs network events in structured JSON format for easy integration with external analysis tools.
-   **Flow Tracking**: Tracks and monitors individual network flows to identify persistent or long-lived connections.

# Systems Engineer View
![Systems Engineering View - GITHUB IMAGE](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/SystemsEngineeringView_Suricata_Final.png) 


# License Summary
The Open Information Security Foundation (OISF) utilizes a [GPL-2.0 license](https://suricata.io/gpl-faqs/) for maintaining the Suricata software. This form of license is recognized as a Copyleft license under the “as-is” Free and Open-Source Software (FOSS) license distinction. This enables contributions to be made to the software provided that specified guidelines are adhered to. The specifications under this license ensure that the software along with any subsequent additions or revisions be available to the users of the software. Additionally, all components pertaining to additions or revisions of the software must comply with the GPL-2.0 license for distribution. 

# Contributor Agreement 
Agreements for contributing to Suricata can be found on their website. Two different forms of agreements are present for those seeking to contribute to Suricata in the form of [individual](https://suricata.io/our-story/contribution-agreement/) and [enterprise](https://suricata.io/our-story/enterprise-agreement/) agreements respectively. Each agreement outlines information pertaining to important areas of note for making contributions to the software whether from independent people or companies. It is necessary to fill out and agree to the information contained within the agreement for making contributions. In addition to the contributor agreements provided for Suricata, a number of steps are provided on how to properly contribute to Suricata through its [documentation site](https://docs.suricata.io/en/latest/devguide/contributing/contribution-process.html). Namely, the process for providing contributions entails how to get into communication with the Suricata community, how to operate with tickets for software, and how to adhere to code and documentation norms. 

# Project Planning w/ Reflection and Contributions 
Some reflections on our teamwork as a whole, we did a great job initially forming the team and getting that finalized. To start with team forming, Matt proactively reached out to Ben and myself via work since we all work for Union Pacific. There were others as well, but they already formed the team. Grace was early reaching out about joining a team and Shane as well. We’re very open minded to backgrounds and want to be welcoming to everyone so we offered and selected them to join the team.  

We had some limited discussions that started early, but we had trouble finding a common time to meet. Nathan setup a ‘when2meet’ and got responses from everyone, but not a single time was available for a group meeting, especially before the planned professor meeting time. Most of us work full time, with limited confidence to “get away” during work. While others had important family commitments and other scheduled classes to attend outside the “9 to 5” work. One reflection we observed on the team size was with the more people we have in a team, it can really help divide and bring a diverse set of experiences to tackle a project like this. However, it can also cause scheduling conflicts like we’ve found. We’re also very proactively handling the scheduling conflicts via meeting in smaller groups, setting clear expectations and more active communication via the Discord server instead of Canvas.  

Shane proposed a discord server to communicate more effectively than Nathan’s original attempt to use the Canvas announcements. It worked and we all get set up pretty well and will use that for our regular meetings. Grace did an excellent job pushing the topic of signup for a professor meeting time, so we booked that to get it in. Ben stepped up and volunteered to be the designated “team lead” but we all worked together to agree upon next steps. 

After meeting with the professor, we immediately met and agreed upon a regular meeting time of Friday during lunch (12pm to 1pm) and that should work.  

We discussed our backgrounds and experiences to start, but then decided to shift to an approach to have each individual offer a few suggestions for open-source projects. We agreed to each come forward with several options and details before our Friday meeting, and we all did so. There was some active banter before the meeting and we all participated in the discussions to arrive on the decision to go with Suricata. We each discussed the scope of the project, familiarity with different tech and goals of interests. 

We then divided the work based on the deliverables and created a deadline to get them done by Monday. The team did great each offering to handle pieces based on their skillset and desired interests. Individuals provided a draft early enough to give others a chance to peer review before Monday, and proactively did provide feedback on the other’s items. All team members met the expectations once we could get them set clearly.  

Here's how we split responsibilities to create initial drafts: 
 - Systems Engineering View: Matt
 - Security Needs, Threats, and Features: Grace
 - Motivation: Ben 
 - OSS project description: Ben 
 - License Summary and Contributor Agreement: Shane 
 - Security History: Grace
 - Project Planning and Reflection: Nathan 
 - Final Delivery in GitHub: Nathan & Shane 

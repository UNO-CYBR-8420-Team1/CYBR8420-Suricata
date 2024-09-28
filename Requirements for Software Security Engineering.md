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

- **Suricata Configuration Guide:** [Link to Suricata's Configuration Documentation](https://suricata.readthedocs.io/en/latest/configuration/index.html)


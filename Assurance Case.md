
# Assurance Cases
## Part 1
### Top-Level Claim 1
![Diagram](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Assurance%20Cases/Assurance%20Case1.drawio.png)
- argument described
### Top-Level Claim 2
- diagram
- argument described
### Top-Level Claim 3
- diagram
- argument described
### Top-Level Claim 4
![Diagram](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Assurance%20Cases/Assurance%20Case%20-%20Logs%20secure%20against%20manipulation.drawio.png)
#### Argument
 There's concern that the network logs that are used to monitor and alert off network activity are not secure from manipulation that would hide a malicious user’s actions while accessing private information like medical records from the hospital’s private network. 

The first immediate doubt is that if someone gained access to the server they’d be able to manipulate the files stored there, including the network logs. To counter this, Suricata has configurations which include the ability to set the file’s access permissions to “600” which means in Linux (the OS of installation) that it’s user process can read and write but no other users have access to it. This presents then an undermining argument that permission configurations could be changed to allow access to those files (by mistake or on purpose). We argue that the configuration file is secure based on a series of evidences.

The second doubt  would be that if the logs are stored only the server, they could be lost (and in turn the evidence of the security breach in the logs. This could be due to purposeful lose of the Suricata server after the initial breach. To secure the logs, Suricata offers the ability to send the logs to another server for replication on a [centralized logging platform]( https://docs.suricata.io/en/latest/output/eve/eve-json-output.html#) common for robust modern infrastructure environments. One can infer based on this that logs being replicated off-device are more secure due to established data security practices. 

The third doubt would be the risk if log flooding with legit traffic can hide malicious actions. To handle this, Suricata offers the common practice of log rotation to divide up the logs. Alone, this log rotation itself initially causes concern that too many logs would cause the rollover and in turn get deleted if the rotation is limited in capacity. However, log deletion is not handled by Suricata. The log capacity concern and limitations implied by rotation is a process handled outside due to the limitations of the hardware platform/capacity. This is outside the scope of the software.

- ### Top-Level Claim 5
- diagram
- argument described
## Part 2
### Alignment of evidence with Top-Level Claims (Assurances)
We found that in several cases (as with log manipulation claim) that the security relies on the configurations themselves being properly configured and secure. With our review we found some evidence of configuration hardening through a series of capabilities/recommendations: First, is using [Landlock]( https://docs.suricata.io/en/latest/configuration/landlock.html#landlock) from the Linux Security Module as of Linux 5.13 to secure the file. Second, [configuration hardening]( https://docs.suricata.io/en/latest/configuration/suricata-yaml.html#configuration-hardening)  can be increased by setting up the “limit-noproc” flag to prevent exploits of Suricata that leveraged from it forking a new process. Third, by establishing a secure environment we can furth harden security by enabling [Address Space Layout Randomization (ASLR)]( https://en.wikipedia.org/wiki/Address_space_layout_randomization) to prevent exploitation of the memory of the system the process is hosted on. Forth, the environment can be even further secured by being installed on a server isolated from the external internet (opposed to the private internal network of the hospital). 


### [GITHUB Project Board Link](https://github.com/orgs/UNO-CYBR-8420-Team1/projects/1/views/2)
### Individual Contributions
Here's how we split the responsibilities to create initial drafts:
  - Top-Level Claim 1: : Ben - Suricata protects the network from DOS attacks.
  - Top-Level Claim 2: : Matt
  - Top-Level Claim 3: : Shane
  - Top-Level Claim 4: : Nathan - The network logs are secure against manipulation.
  - Top-Level Claim 5: : Grace
### Team Reflection
This milestone we were able to work together to brainstorm ideas for different assurance cases. We were able to get the run down for what is expected for this milestone, especially after further explanation from the professor. There were a few spots we had to focus on for our top-level claim assurance cases such as removing “and/or” compound statements to prevent lengthy cases and provide better clarity. In addition to this, thinking more internally vs externally was a spot that needed to be cleared up as well when developing our assurance cases. Also an area where there was a little confusion was that not necessarily all assurance cases will use every component to their diagram that was given as a diagram, we don’t want to force anything that doesn’t necessarily need to be there on the assurance case.

We noted while trying to work through our assurances that the security was often based on the assumption of "proper" configuration and that the configuration wouldn't be manipulated. So the "configuration hardening" was an important aspect of our review, however it also bled into the outside the scope of the software itself security aspect. That being ensuring the operational environment is secure. 
	
We also ran into this operational environment security in other aspects and at what level of detail should we include it. With log manipulation, deletion of logs is handled outside Suricata. Which simplifies the security concern of Suricata itself, as it won't auto-delete if rolling over too fast. However, if not enough space is allocated and alerts on the hardware that it runs on then that will impact Suricata and it's ability to enforce it's assurances. Of course, with denial of services attacks we also ran into this as well since the ability to scale software wise is only one aspect but if the hardware can't keep up that is not the limitation of the Suricata application. ![image](https://github.com/user-attachments/assets/58596513-f27c-4b25-be40-c71d0d4ef431)


### Individual Contributions
DELETE THIS -> LEFT TO REMINDER [Include a reflection on your teamwork for this assignment. What issues occurred? How did you resolve them? What did you plan to change moving forward?]

  - Ben: For my contribution I focused on Top-Level Claim 1 / Assurance 1, “Suricata protects the network from internal DDOS attacks.“ There were a few iterations of assurance cases that I had come out with but I found myself being too generic or too broad that would lead the technical expert astray. In addition to that my focus seemed to be externally vs internally which we had learned from the professor that this ultimately needs to be focused inward. After going through a few iterations I was able to hone more on the internal security side and leave out compound statements to provide more clarity on the assurance case. The plan going forward was to make sure that these were more concise for example my first iteration was so broad on the wording that it wasn't easy for the reader to follow in addition to thinking I needed to add each bit that professor did for his assurance case which resulted in a forced approach which wasn’t correct. Additionally I focused better on the wording aspect to prevent myself from running into doubts by the end user as pointed out by group members. 
  - Matt:
  - Shane:
  - Nathan: Created the initial template for the deliverable document and the initial project tasks in GitHub project tasks. Then created a list of ~8 initial top-level claim ideas to work off of. Also created an initial top-level claim diagram for professor meeting to review together and keep us moving forward with feedback. Nathan tried to provide feedback on Ben's initial top-level claim being too general before that meeting too. Nathan then helped lead the discussion in Ben's absence for our weekly internal team meeting despite not sharing his screen (just the browser) and wasted some time confusing the team. Regardless, the meeting was productive and Nathan kept things moving forward with help from the team of course. Nathan then provided feedback on Ben's argument regarding the evidence being "soft" and not facts as noted. Nathan added contributions to the reflection of the team as well, noting the issue with "proper configuration" being a common trend on our open source software.

  - Grace:


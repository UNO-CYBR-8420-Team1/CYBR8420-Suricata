# Designing for Software Security Engineering
## Part 1: Threat Modeling
### Data Flow Diagram(s)
![Diagram](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Threat%20Modeling%20Brainstorm/DFD-Final.png))
### HTML Report From Microsoft Threat Modeling Tool
## Part 2: Observations
### Design Related Issues With Suricata

#### Operational Environment Based Security
One observation we've seen with the threat analysis is the security of the system is really rooted in the security of the environment it runs in. 
We take highlight of this with the note that the data stores it interacts with are local files that it generates or reads from. Additional to reinforce this is the lack of a "login" and any sort of user interface security might be needed to be put around. Network Admins would interact with Suricata at the Linux terminal and through editing it's configuration file data stores, where access is based on the environment being secure. 

#### Run Mode Considerations
One potential gap we've identified is the security differences based on the "run modes" being used (https://docs.suricata.io/en/latest/performance/runmodes.html). For our limited scope analysis, we used the most secure single process run mode for our analysis to limit the scope of concern and assume a more secure starting point. In industry, it would be critical to review these alternative run modes for analysis since they would help gain performance gains through leveraging multi-threading and load balancing more. Disabling multiple processes from being ran is more secure and this was also brought up in our assurance case 4 where we pointed out the configuration hardening that can be done by enabling thread blocking. 
TODO: Insert DFD draft of alternative "run modes"?

### [GITHUB Project Board Link](https://github.com/orgs/UNO-CYBR-8420-Team1/projects/1/views/2)
### Individual Contributions
- Ben
- Grace
- The Shane
- Matt
- Nathan
### Team Reflection
This milestone working on the Data Flow Diagrams (DFDs) a few issues we ran into initially were making sure to keep the diagram simple, reducing noise of the diagram for better readability for the user and preventing distractions. Our team working on designs wants to keep a thorough understanding of the system but can run into the problem of sometimes over complicating by adding additional external interactions with how the system works not in just the system only environment. Our initial diagrams were trying to incorporate Security Information and Event Manager (SIEM) to show further explanation of possible vulnerabilities, but this ended up being out of the scope of the system specific functionality (back to reducing noise). Another area was expecting there to be a generic data flow for both to and from which was not always the case and we found out could actually end up needing a separate process for if that was always the case. The best way we were able to attack the issues above was by simplifying but not distorting the topics. There were no additional external interactors that needed to be included in the system view if they were not directly related to the system itself. Our group was able to create a few different DFDs and continued to refine to be able to get a more concise deliverable, which after iterations made it clear of troubles we were running into at each step. The plan moving forward is to continue to focus on the system itself without having external interactors such as SIEM distort our view of the system or entice us to add more information than necessary that could distract the customer from what we should be presenting as the final product of the DFD.

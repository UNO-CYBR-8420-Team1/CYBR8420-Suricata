# Code Analysis for Software Security Engineering
## Part 1: Code Review
### Code Review Strategy
#### Review Scope

>>> TODO: Talk about how Shane came up with checklist based on review of diagram and https://cwe.mitre.org/data/definitions/699.html

***
#### CWE Checklist
1) CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory
2) CWE-532: Insertion of Sensitive Information into Log File
3) CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
4) CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
5) CWE-73: External Control of File Name or Path
6) CWE-126: Buffer Over-read
7) CWE-127: Buffer Under-read
8) CWE-125: Out-of-bounds Read
9) CWE-124: Buffer Underwrite ('Buffer Underflow')
10) CWE-349: Acceptance of Extraneous Untrusted Data With Trusted Data

>>>TODO: Shane add more details here 

***

#### Automated Tool Selection
1) SonarCloud
2) CodeQL
3) Fortify
4) Flaw Finder
   
>>> TODO: do we need to add why we picked what? maybe not?
   
#### What challenges did you expect before starting the code review?

>>> TODO:
>>> - Not familiar with C/Rust code

#### How did your code review strategy attempt to address the anticipated challenges?

>>> TODO: 

***
### Manual Code Review Findings

>>> TODO: 

***

### Automated Code Scan Findings
#### Automated #1 [SonarCloud](https://sonarcloud.io/)

(INSERT IMAGES OF ANALYSIS HERE)

[SonarCloud Analysis Output Link](https://sonarcloud.io/summary/overall?id=shellis0_suricata)
***
#### Automated #2 [GITHUB CodeQL](https://github.com/nsteck17/suricata/security/code-scanning)
(INSERT IMAGES OF ANALYSIS HERE)
- About 30 results
***
#### Automated #3 [Fortify Scan](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/UP%20Fortify%20Scan/suricata-version-Fortify_Security_Report.pdf)
(INSERT IMAGES OF PRETTY UI FPR FILE HERE)

>>> TODO: Nathan summerize cleanly why and limitation of scanning this way
- Used Union Pacific local workbench Fortify utility
- Found it only worked on python and other misc files (not C/Rust code)
- FPR file is Foritfy utility format to "pretty format" see results
- PDF file is exhaustive list with details of each
- 
***
## Part 2: Key Findings and Contributions
### Summary of Findings
>>> TODO:
We found common CWEs we expected to find in our checklist in our automated review:
1) CWE-134
>>> TODO: Grace
>>> Description,
>>> Found in files list/link,
>>> Analysis (Manual/Automated),
>>> Summary

***

2) CWE-22
>>> TODO: Matt
>>> Description,
>>> Found in files list/link,
>>> Analysis (Manual/Automated),
>>> Summary

***

3) CWE-73
>>> TODO: Ben
>>> Description,
>>> Found in files list/link,
>>> Analysis (Manual/Automated),
>>> Summary

***

4) CWE-79
>>> TODO: Nathan 
>>> Description,
>>> Found in files list/link,
>>> Analysis (Manual/Automated),
>>> Summary

***

5) CWE-14 or CWE-367
>>> TODO: Shane 
>>> Description,
>>> Found in files list/link,
>>> Analysis (Manual/Automated),
>>> Summary

***
>>> TODO: Overall notes? maybe not?

### Ongoing Contributions
### [GITHUB Project Board Link](https://github.com/orgs/UNO-CYBR-8420-Team1/projects/1/views/2)
### Individual Contributions
- Ben
  - TODO
- Grace
  - TODO
- Shane
  - TODO
- Matt
  - TODO
- Nathan
  - I started off by immediately attempting to fork the Suricata OOS GitHub codebase and get a quick setup of whatever running I could. However, I wasn't successful and didn't get back to it until after thankgiving when I could touchbase with Shane and Ben on 12/01/2024. Ben was attempting to get CodeQL running as well, so we prevent further duplication of efforts and I was able to get CodeQL setup working the next day and updated the team. I also leveraged my work's Fortify scanning installation at Union Pacific to attempt to scan the sourcecode however the tools were not configured for the C/Rust programming language and we got minimal results (we primarly focuses on Java and Javascript). In the group meeting I participated in our group discussion and the pressed to keep us organized and actionable by dividing up the assignments of individual deep dive of specific CWEs we found in our scan results so we can all make steps forward on individual contribution. I chose CWE-79 based on my initial review of CodeQL and the related code I tried to review that it reported with it. I am familiar with C++ from undergrad school years ago, but the C/Rust code took a bit to understand how to read. 
***
### Team Reflection
>>> TODO:
>>> Notes (from Nathan to get this started and add points):
>>> - Would of tried to meet and organize more about use cases and how CWE they tied to our use cases
>>> - Might of been good to do a high level code review together of the source code, the holiday really gave us time, but we had trouble using that extra time effectively at the start getting everyone together. 
>>> - Big win that we each picked an automation tool to try to get working to correlate results of CWE between each
>>> - Did a great job in our group discussion trying to wrap our head around the tasks together and set expectations, and we get along together great which is good. 

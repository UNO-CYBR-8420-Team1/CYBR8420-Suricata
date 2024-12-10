# Code Analysis for Software Security Engineering
## Part 1: Code Review
### Code Review Strategy
#### Review Scope
Our team started out the code review strategy by taking our past deliverables such our systems engineering design diagram, misuse cases, assurance claims, and threat model analysis into consideration. With these deliverables, we consulted the [MITRE CWE View for Software Development](https://cwe.mitre.org/data/definitions/699.html) and conducted an intial manual review of CWEs to collect a checklist of those that could apply to Suricata in terms of software weaknesses in accordance with what our group has learned about Suricata previously. After we had collected our initial checklist of CWEs to look for during code analysis, we utilized a variety of automated code scanning tools to potentially confirm and reinforce our intial findings as well as to bring additional CWEs to our attention that were not previously considered. Following the use of automated code scanning tools, our group selected a small number of CWEs that aligned with our initial checklist as well as additional CWEs found to be of significance due to the code files in Suricata they were associated with to discuss in further detail or provide a more descript manual review of. The use of multiple automated tools was helpful to our analysis as it, in addition to presenting us with different CWEs, allowed us to find commonalities between our checklist and between other utilized tools.

***
#### CWE Checklist
1) [CWE-538](https://cwe.mitre.org/data/definitions/538.html): Insertion of Sensitive Information into Externally-Accessible File or Directory
2) [CWE-532](https://cwe.mitre.org/data/definitions/532.html): Insertion of Sensitive Information into Log File
3) [CWE-22](https://cwe.mitre.org/data/definitions/22.html): Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
4) [CWE-73](https://cwe.mitre.org/data/definitions/73.html): External Control of File Name or Path
5) [CWE-125](https://cwe.mitre.org/data/definitions/125.html): Out-of-bounds Read
6) [CWE-126](https://cwe.mitre.org/data/definitions/126.html): Buffer Over-read
7) [CWE-127](https://cwe.mitre.org/data/definitions/127.html): Buffer Under-read
8) [CWE-349](https://cwe.mitre.org/data/definitions/349.html): Acceptance of Extraneous Untrusted Data With Trusted Data

***

#### Automated Tool Selection
1) SonarCloud
2) CodeQL
3) Fortify
4) Flaw Finder
   
Our team decided to use a handful of automated code analysis tools to get a chance to utilize a diverse set of tools while providing a comprehensive report of these findings. The ability to run more than one automated code analysis tool allows us to see what other tools are also finding to see if there is any noise or really hone in on particular areas of focus. The flip side of this is that we could also run into more noise that needs to be sifted through to better see if it's a true vulnerability or issue for our system. The above are the tools we utilized and the results of our findings can be found below.
   
#### What challenges did you expect before starting the code review?
Some challenges we expected before starting the code review were realising we aren’t super familiar with C or Rust code so that could prove a challenge for understanding our results. However, our code analysis tools allow us to have a better understanding of what it found while also providing an example and finding it in our code to give a better comprehension of our alert to our OSS code. Additionally, not coming from any prior knowledge for some team members and doing this for the first time proved to not necessarily be a huge challenge but a new one to take on and better understand how professionals review code on a daily basis allowing us to gain some exposure. We also knew if we all were doing different tools that trying to navigate them could be a little bit of a challenge and that the results we get from them could turn out to be noise and not necessarily something that needs to have attention put on immediately. 

#### How did your code review strategy attempt to address the anticipated challenges?

>>> TODO: 

***
### Manual Code Review Findings

>>> TODO: 

***

### Automated Code Scan Findings
#### Automated #1 [SonarCloud](https://sonarcloud.io/)

One of the automated tools that has been used to scan the Suricata codebase has been SonarCloud. This particular automated code scanning tool was leveraged due to its availability for use with both public and open-source repositories from GitHub and other sources without need a of a subscription, easy integration into GitHub's code scanning functionality, and it's compatibility with a variety of coding languages. The Suricata open-source software project includes multiple languages with its majority having been written in the C programming language and other significant shares being written in Rust, Python, and more. This versatility from the tool allowed for the spotting of issues from not just one specific code region or language comprising Suricata but the whole application. Upon review of the analysis results, it was found that many of the issues raised for the Suricata codebase pertained to issues of reliability and maintainability with 84 and 7,651 issues for the two categories respectively. For issues relating to security, which is the primary area of interest of the application for this course, there were a much more manageable  24 issues raised. A link to the overall analysis report generated by SonarCloud is provided below. It is the security issues highlighted in the report which will be the primary talking point of the tool's findings.

[SonarCloud Analysis Output Link](https://sonarcloud.io/summary/overall?id=shellis0_suricata)

![image](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/SonarCloud%20Scan%20Reults%20Image.png)

As can be seen in an image listing the security issues provided from the SonarCloud analysis above, the 24 issues aligned with two distinct concerns with the first concern being found twice and the second concern being found in multiple instances of the codebase. Both of the topics of concern found within the security issues of the tool aligned with CWEs, both of which were not concerns identified within our initial CWE checklist.

The first concern discussing TOCTOU vulnerabilities aligned with CWE-367 and was found both times within a singular file, `src/conf-yaml-loader.c`. The general details of the CWE involve the software security weakness associated with the actions of checking and utilizing code and the periods of time between those events allowing for potential exploits to occur. This finding, more specifically the file for which the CWE was linked, was found to be a key area of focus for the code analysis as the weakness mentioned impacted the file responsible for loading and parsing the YAML configuration file used by Suricata. From previous project deliverables concerning use cases and misuse cases, assurance cases, and threat modeling the configuration component of Suricata, through its YAML file, was a recurring area of great importance as it is in charge of the setup and management of Suricata.

The second concern was identified across 22 security issues listed in the automated analysis spanning 22 separate C source code files. Each of the source files listed with the issues pertaining to this concern were files responsible for various alerts, logs, outputs, and utilities. This concern aligned with CWE-14 which is a weakness involving memory handling where the compiler chooses to optimize by not accessing memory rather than clearing it as specified by source code implementations. This weakness was also found to be important as another major component to Suricata's operation is its capacity to output information relating to information flowing across the network it is responsible for analyzing. It is able to do this, as has been learned through previous deliverables, in a variety of ways the most notable which being alerting and logging mechanisms for reporting on network activity. CWEs being listed in relation to these areas of code could be of importance as they too are a parts of prominent feature from the software.

Below is a table comprising the CWEs acquired from the SonarCloud tool alongside relevant information and affected files for further viewing. More detailed coverage of the respective CWEs from this tool beyond initial findings will be evaluated further within part two of the deliverable below. 

| **Security Issue** | **Severity** | **CWE Entry** | **Affected Files** |
| :--------------------------------------------------------- | :--: | :------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------- |
| Acessing files should not introduce TOCTOU vulnerabilities | High | [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367) | [src/conf-yaml-loader.c](https://github.com/OISF/suricata/blob/master/src/conf-yaml-loader.c) |
| "memset" should not be used to delete sensitive data       | High | [CWE-14: Compiler Removal of Code to Clear Buffers](https://cwe.mitre.org/data/definitions/14.html)      | Some examples include: [src/alert-debuglog.c](https://github.com/OISF/suricata/blob/master/src/alert-debuglog.c), [src/log-tcp-data.c](https://github.com/OISF/suricata/blob/master/src/log-tcp-data.c), [src/output-json-file.c](https://github.com/OISF/suricata/blob/master/src/output-json-file.c), [src/util-logopenfile.c](https://github.com/OISF/suricata/blob/master/src/util-logopenfile.c) |

***

#### Automated #2 [GITHUB CodeQL](https://github.com/nsteck17/suricata/security/code-scanning)
Incase access to the Fork and scan results are limited, here's a PDF of the pages: 
- [Forked Suricata CodeQL PDF Page 1 of 2](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/CodeQL/Code%20scanning%20alerts%20%C2%B7%20nsteck17_suricata%20-%20P1.pdf)
- [Forked Suricata CodeQL PDF Page 2 of 2](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/CodeQL/Code%20scanning%20alerts%20%C2%B7%20nsteck17_suricata%20-%20P2.pdf)

![image](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/CodeQL/Screenshot%202024-12-07%20093638.png)

When creating the fork of Suricata, at first we struggled to get it working with CodeQL. We learned this is because the C code's build commands were not valid for the default CodeQL generated approach. After some trial and error (and educated review how CodeQL is setup/works) we finally saw that it is based on the .github/workflows/codeql.yml configuration and actually Suricata's source code actually already had an "advanced" setup [here](https://github.com/OISF/suricata/tree/master/.github/workflows) and finally we were able to get some results. 

Our initial checklist of CWEs identified CWE-22 and CWE-73 that was found in by results of the CodeQL scans, confirming our original thoughts. 
These both were associated to instances of "Uncontrolled data used in path expression" findings which there were three separate entries for in the results set. 
![image](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/CodeQL/Screenshot%202024-12-07%20100156.png)
  
***

#### Automated #3 [Fortify Scan](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/UP%20Fortify%20Scan/suricata-version-Fortify_Security_Report.pdf)
![image](https://github.com/user-attachments/assets/052d0c3a-76dc-404b-b345-d74d219df8c1)

Nathan setup the Fortify scan using his work's (Union Pacific Railroad) provided Fortify utility scanning setup and default rules there (not on a GitHub integration). He thought this would be a good "industry standard" approach as this is the same scan the rest of the code that runs in production goes through. Interestingly enough though it didn't actually scan all the C and Rust language files. It specifically captured the Python and other utility files (like Docker) where credentials are stored. So the results were not fully "inclusive" but it did give an interesting unique insight others may not be able to do.

Linked are a PDF of results, but it's important to note the scan also produced an "FPR" file that could be opened by Fortify workbench software. This makes it easier to review the scan results in a more "user friendly" way with more details. This includes full code references and additional details not seen in the PDF output. 

#### Automated #4 [Flaw Finder](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/flawfinder_results.txt)
Flawfinder is a static analysis tool specifically designed for C and C++ programs. This language is used in our open-source projects Suricata. Writing in this language is prone to common security vulnerabilities such as buffer overflows, format string vulnerabilities, and unsafe memory operations. Flawfinder is a suitable choice because:

- **Targeted for C/C++:** It has a comprehensive database of over 200 rules targeting common pitfalls in C/C++ codebases.
- **Quick Analysis**: It provides rapid analysis of large codebases, identifying vulnerabilities with minimal setup.
- **Free and Open-Source:** As an open-source tool, Flawfinder aligns well with the ethos of analyzing other open-source projects like Suricata.
- **Granular Reporting:** It categorizes findings by risk levels, allowing teams to prioritize remediation efforts effectively.
- 
**How Flawfinder Works**
Flawfinder operates by:
- **Parsing Source Code**: It examines the source files line by line to identify potentially dangerous functions and constructs.
- **Matching Patterns**: It matches code patterns against a database of known vulnerable functions (e.g., printf, system, random).
- **Assigning Risk Levels**: Each finding is assigned a risk level from 0 (low) to 5 (high), helping developers prioritize their attention.
- **Providing Recommendations**: The tool offers practical suggestions for mitigating the identified vulnerabilities.
- **Performance Metrics**: Flawfinder also provides performance statistics, such as lines of code analyzed per second, and summarizes the overall risk.

**Results**
Before running Flawfinder, the first step was to obtain a local copy of the Suricata source code. This was achieved by cloning the project's Git repository, which provides access to the full codebase.
![image](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/Screenshot%202024-12-08%20143309.png)

- **Format String Vulnerabilities (CWE-134)**

printf in /plugins/napatech/util-napatech.h:86 and ./src/suricata-common.h:408

snprintf in ./src/util-print.h:28

syslog in ./src/win32-syslog.h:78

Severity Level: 4

**Impact**: If format strings can be influenced by an attacker, they may exploit these functions to execute arbitrary code or read sensitive memory.

- **Command Execution Vulnerabilities (CWE-78)**
  
system in ./src/suricata.h:144 and ./src/util-reference-config.h:37

Severity Level: 4

**Impact:** The system function executes shell commands, making it vulnerable to injection attacks if input is not properly sanitized.

- **Weak Random Number Generation (CWE-327)**
  
Instance: random in ./src/app-layer-ssl.h:254

Severity Level: 3

**Impact**: The random() function is predictable and unsuitable for cryptographic purposes, such as generating keys or nonces.
***

***
## Part 2: Key Findings and Contributions
### Summary of Findings
1) [CWE-134](https://cwe.mitre.org/data/definitions/134.html) **Use of Externally-Controlled Format String**
#### Description
CWE-134 refers to a class of vulnerabilities that arise when user-controlled input is used as a format string in functions such as **printf, snprintf, fprintf, or syslog** without proper validation. This vulnerability can allow attackers to execute arbitrary code, crash the application, or gain access to sensitive information.

#### Found in files
- **Format String Vulnerabilities (CWE-134)**

printf in /plugins/napatech/util-napatech.h:86 and ./src/suricata-common.h:408

snprintf in ./src/util-print.h:28

syslog in ./src/win32-syslog.h:78

Severity Level: 4

**Impact**: If format strings can be influenced by an attacker, they may exploit these functions to execute arbitrary code or read sensitive memory.

#### Analysis
Flawfinder scans the source files in the repository for .c and.h files and breaks down the code into tokens and syntax elements for analysis. In this case, it scanned files like:

- /plugins/napatech/util-napatech.h
- ./src/suricata-common.h
- ./src/util-print.h
- ./src/win32-syslog.h

<img width="302" alt="image" src="https://github.com/user-attachments/assets/d8557f09-58c7-466d-a012-89a9e375b25d">


#### Summary

It seems like Flawfinder analysis of the Suricata codebase identified multiple instances of CWE-134. These vulnerabilities occur when user-controlled input is used as a format string, potentially allowing attackers to execute arbitrary code, crash the application, or expose sensitive information. This is an interesting finding as other automated tools may have found this as a vulnerability but not as an emphasis.
***

2) [CWE-22](https://cwe.mitre.org/data/definitions/22.html) **Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')**
### Description
CWE-22 is a weakness that stems from a failure to validate user input when specifying a path or directory name. A malicious user could insert special sequences of characters into 
the specified path or directory ("../", for example) that may allow the user to access unintended/unauthorized files/directories.
### Found in Files List/Link
Line 1182 of suricata/src/util-debug.c
![image](https://github.com/user-attachments/assets/a48a46e7-f399-4662-9021-3b923c1acb93)

Line 185 of rust/target/release/build/suricata-lua-sys-efab3431b2955876/out/lua/luac.c
Line 374 of rust/target/release/build/suricata-lua-sys-efab3431b2955876/out/lua/luac.c

### Analysis Via CodeQL
CodeQL warned of CWE-22 existing in the Suricata codebase at the locations specified above. Specifically, when looking at the code snippet of suricata/src/util-debug.c, one can observe that the variables in the “SC_LOG_OP_IFACE_FILE” case do not have any sort of validation applied to them. This could lead to cases highlighted in CWE-22 where a user could utilize syntax like “../” to access unauthorized directories and paths. In a hospital setting, users that are able to traverse unintended paths could easily navigate to directories that contain personally identifiable information. This would be a major breach of HIPAA and could lead to serious consequences for the hospital if this weakness is not mitigated.
### Summary
The high-severity CWE-22 weakness in Suricata highlighted by the CodeQL analysis has the potential to critically impact the hospital by way of a major HIPAA violation. A best practice would be to sanitize input from users by using [input validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) to prevent users from submitting unexpected data and accessing different data paths and directories. 


***

3) [CWE-73](https://cwe.mitre.org/data/definitions/73.html) **External Control of File Name or Path**
#### Description
The product allows user input to control or influence paths or file names that are used in filesystem operations. 
#### Found in files list/link
| File Name                 | Line Number                                                                        |
| :------------------------ | :--------------------------------------------------------------------------------: |
| rust/target/release/build/suricata-lua-sys-efab3431b2955876/out/lua/lua.c:374    | [374](https://github.com/nsteck17/suricata/security/code-scanning/12)      |
| rust/target/release/build/suricata-lua-sys-efab3431b2955876/out/lua/luac.c:185       | [185](https://github.com/nsteck17/suricata/security/code-scanning/13)      |
| src/util-debug.c:1182         | [1182](https://github.com/nsteck17/suricata/security/code-scanning/14)         |


#### Analysis CodeQL
![image](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/CWE73Ex.PNG)

As mentioned above there were three instances that CodeQL had found through the GitHub scan. There is a brief image above that shows the "Uncontrolled data used in path expression" [#14](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/CodeQL/Screenshot%202024-12-07%20100156.png) of Code Scanning Alerts as part of the code analysis from CodeQL. The analysisdescribes the results of this making it possible for a malicious actor to access resources that shouldn't normally be access such as files. For our environment in a healthcare industry, Health Insurance Portability and Accountability Act (HIPAA), is a huge concern along with Personally Identifiable Information (PII) the only people that should have access to this information are ones appointed by the administrators of the system and no malicious actors. As stated by the review a validation could prevent this from being a problem with the file names to prevent such a trouble of manipulation or unauthorized access to a restricted file. The review of this particular analysis comes close to our [Assurance Case #3](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Assurance%20Case.md#assurance-case-3) where rules and files are set up not only to detect but also prevent unauthorized access. This efforts prevent the system from being completely vulnerable attacks and allow unauthorized access to be mitigated.

#### Summary
The automated run offered plenty of suggestions to look into as a possible vulnerability spot, along with pointing the area of concern out was ways to remedy or best practices to stay away from external entity gaining unauthorized permission to this area such as restricting file name, creating an allow list, and also being aware of path separators. As mentioned in the analysis portion this comes back to our Assurance Case #3 where our system has measures put into place to prevent such cases. The part of code that CodeQL found would be a good area of focus to prevent external influences and prevent any compromise to our OSS.

***

4) [CWE-95](https://cwe.mitre.org/data/definitions/95.html) **Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')**
#### Description
CWE-95 is defined as "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')". The code receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before using the input in a dynamic evaluation call (e.g. "eval"). This may allow an attacker to execute arbitrary code, or at least modify what code can be executed.

#### Found in files
[LINE 259 of suricatasc.py](https://github.com/OISF/suricata/blob/master/python/suricata/sc/suricatasc.py#L259)
![image](https://github.com/user-attachments/assets/3510aa98-ecd7-4c16-a946-af609c372571)

#### Analysis
The Fortify Scan produced an FPR file with results that could be opened with it's Fortify Workbench Tool (and a summary PDF of results). We took a screenshot of the workbench utility reporting these results.
![image](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/UP%20Fortify%20Scan/1-critical-cwe95-cwe494-cwe094.PNG)

#### Summary
The automated fortify scan found this "Critical" issue of accepting user input. However I believe it is a false positive based on my review. Specifically the Fortify vulnerability and CWE is indicating that user input is not sanitized before being executed. However, once you review the rest of the code starting with the function's name you see that it's interactive user input and more specifically the user is selecting from the list of options of commands. If the user is not allowed to enter anything like they, the vulnerability doesn't actually exist. 
![image](https://github.com/user-attachments/assets/db21cf22-8fea-4b59-b99d-34c0963fd4b5)

This is command-line interfaces so they're not able to "hack" the UI to enter invalid inputs another way. They only are given a set of options. 
![image](https://github.com/user-attachments/assets/a17c3f9c-a2d0-4fb3-8c42-2a23e963f0ea)

So based on my findings this is actually a false positive. I picked this example due to it being reported as critical, easily visibility manually reviewed and actually a false positive. From experience, this is a very REAL situation in industry. I (Nathan) work at Union Pacific Railroad and we use automated Fortify Scan results in our CI/CD pipeline for deployments to prevent code from going to prod if they have a critical vulnerability like this. So this would not be "deployable" to production based on this without an exception. As well, when we delivered code to a client (the Norfolk Southern Railroad) we had to provide these Fortify scan results to prove none were in the deliverable executable code we provided. I find these scenarios a very good example of how automation isn't perfect. 

***

5) [CWE-367](https://cwe.mitre.org/data/definitions/367) **Time-of-check Time-of-use (TOCTOU) Race Condition**
#### Description
As was briefly mentioned in the automated code scan findings pertaining to SonarCloud, CWE-367 identifies the weakness "Time-of-check Time-of-use (TOCTOU) Race Condition". This weakness involves both software states and timing where a malicious actor may try to gain access to the affected software, in this case the configuration file of Suricata, in order to conduct some unsavory actions within the system. The malicious action outlined in this weakness would happen in the time that has elapsed between the moment a piece of software has had its state verified for its integrity and the time when the software is put to use. This finding has relevance to Suricata as the weakness has been found to be most impactful in software like Suricata that has an emphasis on "files, memory, or even variables in multithreaded programs". 

#### Affected files
The file in which the CWE was raised from the automated scan was in src/conf-yaml-loader.c on [line 500](https://github.com/OISF/suricata/blob/master/src/conf-yaml-loader.c#L500) and [line 578](https://github.com/OISF/suricata/blob/master/src/conf-yaml-loader.c#L578).

**Line 500** \
![image](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/Suricata%20CWE-367%20Image%201.png)

**Line 578** \
![image](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/Suricata%20CWE-367%20Image%202.png)

#### Analysis
Based on the images provided for the associated file, the two security issues raised for this CWE pertain to a specific implementation seen within the file for parsing the YAML configuration. In particular, the code snippet under scrutiny is in regard to how the file is being opened using `fopen()` for reading purposes on two separate lines. The code fragment identified is `infile = fopen(filename, "r")` where `infile` is a file pointer (denoted as `FILE*`), `filename` is a character pointer (denoted as `char*`), and `"r"` is a character pointer passed into the function specified to serve as the mode in which the file will be opened which is for reading in this case.

The problem derived from the two images below provided from the SonarCloud analysis relate to the order of operations used for handling the configuration file reads within the parsing source file for loading the YAML file with and without prefixes. Both instances show the checking being conducted for each respective file open taking place prior to attempting to open the file for reading which alludes to the TOCTOU vulnerability potential occurring between the file verification and open steps within the code at each location. The official documentation page for CWE-367 outlines a variety of possible mitigations to consider for this particular issue. While SonarCloud provides an example of code that would mitigate the weakness, the example listed applies to the action of opening a file for writing by adding an additional check for whether the file exists beforehand through the use of the `"wx"` mode. This example would not be directly translatable to instances of reading from a file however as there is no equivalent mode available for opening a file for reading according to [documentation](https://cplusplus.com/reference/cstdio/fopen/) on `fopen()` as the file must exist in order to be read from in the first place.

Other potential mitigations that could be considered for these cases could include rearranging the order of the two operations such that the `fopen()` function would precede the file verification using `stat()`, implementing  an additional verification check after opening the file, implementing an additional design measure to monitor file accessors, or to limit access times of the file to reduce the potential window of access between the initial verification check and file open by a malicious actor. Both of the analysis images show comments denoting the TOCTOU vulnerability in relation to another analysis tool by the name of [Coverity](https://scan.coverity.com/), so it appears that the developers of Suricata are aware of this possible weakness for both instances but we are not certain of their intentions for this code as of this time.

**File Check Prior to Line 500** \
![image](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/Suricata%20CWE-367%20Results%20Image%201.png)

**File Check Prior to Line 578** \
![iamge](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/Suricata%20CWE-367%20Results%20Image%202.png)

#### Summary
This CWE was one of two CWEs provided by the automated code scan conducted using SonarCloud. This particular CWE was found to be a standout aside from other CWEs obtained from our initial CWE checklist as well as CWEs obtained from other automated tools. We felt it should receive a more detailed manual review due to the potential impact it could have on the configuration file of Suricata as that is a highly important component of the software. The Suricata YAML file has been highlighted in previous deliverables, most notably our [threat modeling deliverable](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Designing%20for%20Software%20Security%20Engineering.md), as a key area of focus as it is the commanding file for how Suricata is to act and report information. Thinking to our perceived hospital environment, the consequences resulting from a TOCTOU vulnerability could lead to serious security concerns as a malicious actor could directly interfere with how Suricata is configured to run within a hospital system causing slow downs or crashes limiting the effectiveness of tool and lower the protections it provides through network analysis. The reduced protection resulting from the aforementioned action could enable the malicious actor to interfere with medical devices or inject malicious code into Suricata as has been discussed in our [third](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Requirements%20for%20Software%20Security%20Engineering.md#usemisuse-case-3-intrusion-preventing-system) and [fifth](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Requirements%20for%20Software%20Security%20Engineering.md#usemisuse-case-5-rule-configuration-management) misuse cases within our [SSE requirements deliverable](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Requirements%20for%20Software%20Security%20Engineering.md).

***

6) [CWE-14](https://cwe.mitre.org/data/definitions/14.html) **Compiler Removal of Code to Clear Buffers**
#### Description
Also touched on from the automated scan results returned from SonarCloud was the identification of CWE-14 which concerns the "Compiler Removal of Code to Clear Buffers". In this instance 22 separate files, listed in the table found below, were connected to this CWE. The concern of this CWE is with the manner in which a compiler may handle memory deallocation actions. Some compilers may choose to omit the action during compilation which could result in the persistence of memory containing private information. The significance of this CWE with respect to Suricata comes from affected files which include many of those responsible for the reporting features of the software application.

#### Affected Files
| File Name                 | Line Number                                                                        |
| :------------------------ | :--------------------------------------------------------------------------------: |
| src/alert-debuglog.c      | [411](https://github.com/OISF/suricata/blob/master/src/alert-debuglog.c#L411)      |
| src/alert-fastlog.c       | [215](https://github.com/OISF/suricata/blob/master/src/alert-fastlog.c#L215)       |
| src/log-httplog.c         | [538](https://github.com/OISF/suricata/blob/master/src/log-httplog.c#L538)         |
| src/log-stats.c           | [200](https://github.com/OISF/suricata/blob/master/src/log-stats.c#L200)           |
| src/log-tcp-data.c        | [201](https://github.com/OISF/suricata/blob/master/src/log-tcp-data.c#L201)        |
| src/log-tlslog.c          | [160](https://github.com/OISF/suricata/blob/master/src/log-tlslog.c#L160)          |
| src/log-tlsstore.c        | [379](https://github.com/OISF/suricata/blob/master/src/log-tlsstore.c#L379)        |
| src/output-eve-stream.c   | [106](https://github.com/OISF/suricata/blob/master/src/output-eve-stream.c#L106)   |
| src/output-filestore.c    | [297](https://github.com/OISF/suricata/blob/master/src/output-filestore.c#L297)    |
| src/output-json-alert.c   | [888](https://github.com/OISF/suricata/blob/master/src/output-json-alert.c#L888)   |
| src/output-json-anomaly.c | [327](https://github.com/OISF/suricata/blob/master/src/output-json-anomaly.c#L327) |
| src/output-json-dns.c     | [478](https://github.com/OISF/suricata/blob/master/src/output-json-dns.c#L478)     |
| src/output-json-drop.c    | [237](https://github.com/OISF/suricata/blob/master/src/output-json-drop.c#L237)    |
| src/output-json-file.c    | [282](https://github.com/OISF/suricata/blob/master/src/output-json-file.c#L282)    |
| src/output-json-frame.c   | [484](https://github.com/OISF/suricata/blob/master/src/output-json-frame.c#L484)   |
| src/output-json-http.c    | [641](https://github.com/OISF/suricata/blob/master/src/output-json-http.c#L641)    |
| src/output-json-smtp.c    | [186](https://github.com/OISF/suricata/blob/master/src/output-json-smtp.c#L186)    |
| src/output-json-stats.c   | [411](https://github.com/OISF/suricata/blob/master/src/output-json-stats.c#L411)   |
| src/output-json-tls.c     | [547](https://github.com/OISF/suricata/blob/master/src/output-json-tls.c#L547)     |
| src/output-lua.c          | [882](https://github.com/OISF/suricata/blob/master/src/output-lua.c#L882)          |
| src/stream-tcp.c          | [6042](https://github.com/OISF/suricata/blob/master/src/stream-tcp.c#L6042)        |
| src/util-logopenfile.c    | [927](https://github.com/OISF/suricata/blob/master/src/util-logopenfile.c#L927)    |

#### Analysis
Following a review of each of the affected files, the recurring element seen among each of the file entries is in relation to the use of `memeset()`. In each instance a specific location in memory is being accessed to be assigned the `0` to clear out the indicated memory to the full size of the memory location. An alternative suggested to address this CWE would be to consider the use of an alternative to `memset()` denoted `memset_s()`. According to [documentation](https://en.cppreference.com/w/c/string/byte/memset) for `memset_s()`, the function be behaves like `memset()` with the inclusion of an additional input parameter for the size of the memory location being focused on, which too could be filled with the size of the memory location as is currently being done. The benefit utilizing `memset_s()` is that it would not be optimized out of compilation owing to a more definitive memory deallocation process.

#### Summary
Similarly to CWE-367, this weakness was provided a closer manual review due to the files that were associated from Suricata as well as its similarity with our [fourth misuse case](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Requirements%20for%20Software%20Security%20Engineering.md#usemisuse-case-4-log-analysis-and-manipulation) from a previous project deliverable. The reporting features of Suricata are core to its use much like that of its configuration. With it acting as a network analysis tool, it is vital for it to function as it is intended to be able to continue reporting on potential malicious activities. This holds relevance to a hospital environment as administrators are responsible ensuring disruptions are not experienced over the hospital network. Likewise, it is of critical importance that no valuable information is acquired  by malicious users such as those of patients or caregivers. While not all reports generated by Suricata will be of value to those seeking to cause harm to an environment, there will likely be information present in reporting files that would be of interest in order to case a system or network for possible points of exploitation. The possibility of not clearing reporting information fully from memory, depending on compiler selection and configuration, could feed this weakness allowing for said problems to be experienced.

***

### Ongoing Contributions
Team 1’s planned or ongoing contributions to the upstream OSS consist of keeping an eye on further developments of Suricata. There seems to be areas where the OSS can be improved such as a login function, integration with more SIEM like functions within the software if Suricata has aspirations of taking on such ideas to better sift through the data that it collects and permission based roles. As for code changes, our group is not as well versed on C and Rust code so the upkeep and contribution wouldn’t be much on the code change help. However, following up with recent implementations, updates, and understanding the news letters that are released help us stay more up to date and what to expect when reviewing OSS systems in an open source community. Suricata had a recent release and implementation as of October 1, 2024 and the community continues to support and fix vulnerabilities. As a group we would like to periodically stay on top with trends that we work with in our own environments and see possibly how they could contribute to other OSS systems.

Keeping in mind for future vulnerabilities or security troubles here are the steps we would need to take / other OSS supports as follows:

![image](https://github.com/UNO-CYBR-8420-Team1/CYBR8420-Suricata/blob/main/Code%20Analysis%20Brainstorm/Suricata%20Reporting%20Steps.PNG)

### [GITHUB Project Board Link](https://github.com/orgs/UNO-CYBR-8420-Team1/projects/1/views/2)
### Individual Contributions
- Ben
  - My contribution to this milestone was helping get github documents set up and project board issues created to help kickstart this portion of the project. I along with Nathan had found out we were both utilizing CodeQL after finding out we were working on it at the sametime I was able to utilize Nathan’s fork of Suricata and scans. My focus was on CWE-73 which was External Control of File Name or Path which would allow unauthorized user input to alter certain file system tasks. There were about 3 different spots that were identified with this run that CodeQL had found when running the automated scan. Our team utilized multiple different automated systems to better get a comprehensive analysis across the tools to see how they vary between them and catch any commonalities between the tools. In addition to this my contributions were also with the reflection, ongoing contributions, and other portions of the document to make it concise and cohesive. I worked with the group to get the final deliverable of our project to the finish line while going over formatting, grammar, and readability to the customer. Additionally, I helped contribute as team lead to assist with professor meetings, group meetings, and help facilitate tasks on time to help remind teammates about upcoming deadlines.
- Grace
  - In our team's systematic code review for Suricata, I contributed by leveraging Flawfinder tool to conduct an automated scan of the codebase, focusing on identifying vulnerabilities. This effort was part of a broader scenario-based approach, scoping the review to modules most relevant to identified misuse cases, assurance claims, and threat models. My role involved analyzing the flagged results from Flawfinder, validating the findings. I particularly focused on mapping CWE-134, which we determined to be common with other automated scans. Specifically, I identified vulnerabilities in functions such as printf, snprintf, and syslog. This contribution enhanced the depth of our findings and underscored the importance of secure coding practices for protecting Suricata against format string exploits. Additionally, I collaborated with teammates to document the code review strategy, share findings, and integrate this analysis into our team’s deliverables. 
- Shane
  - TODO
- Matt
  - TODO
- Nathan
  - I started off by immediately attempting to fork the Suricata OOS GitHub codebase and get a quick setup of whatever running I could. However, I wasn't successful and didn't get back to it until after thankgiving when I could touchbase with Shane and Ben on 12/01/2024. Ben was attempting to get CodeQL running as well, so we prevent further duplication of efforts and I was able to get CodeQL setup working the next day and updated the team. I also leveraged my work's Fortify scanning installation at Union Pacific to attempt to scan the sourcecode however the tools were not configured for the C/Rust programming language and we got minimal results (we primarly focuses on Java and Javascript). In the group meeting I participated in our group discussion and the pressed to keep us organized and actionable by dividing up the assignments of individual deep dive of specific CWEs we found in our scan results so we can all make steps forward on individual contribution. I chose CWE-95 to do a deep dive on (with an example) based on my initial review of Fortify results and the related code. I am familiar with C++ from undergrad school years ago, but the C/Rust code took a bit to understand how to read. I also tried to put together the structure of the deliverables and first set of details for the team to try to build off of based on our team's initial agreement of how to layout details (adding notes to the reflection and other sections of this submission). 
    
***
### Team Reflection
This milestone proved to have some challenges in terms of working around holidays to meet with team members but we were able to overcome this by working through chat, Friday meetups, and discord calls. We were able to start out with an initial manual code analysis to get CWEs that may align with our OSS. We found that after doing a manual analysis and then pairing that with automatic analysis there were commonalities to help reinforce that this would be a great place to hone in on our CWEs. Our group chose to use several different automatic code analysis tools which ultimately worked in our favor to see what matched and if we were on the right track. The idea that we had some similar CWEs on different code tools didn’t necessarily mean those were all concrete and fit to our system but allowed us to take a closer look at the results that ultimately had ones that were true to our OSS. One of the tougher parts was combing through all of this data and making sure it was relevant to our system. In some cases it felt like there was a lot of noise being presented to us, however after utilizing multiple code analysis scans we could narrow the results down to our system needs. Additionally our group did a great job in our group discussion working around tasks and making clear expectations which allowed us to work cohesively for this section of milestone.

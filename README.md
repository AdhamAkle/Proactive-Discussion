# Proactive-Discussion

Suricata analysis and network capturing

1.	I began by capturing network traffic using Wireshark while executing the Zeus malware for analysis.
 

2.	I incorporate the default rule sets for Suricata from the official Emerging Threats repository, specifically the emerging-malware.rules and emerging-phishing.rules files.

3.	I have developed a set of detection rules specifically designed to identify Zeus malware. Below is a detailed explanation of these rules.


-	HTTP C2 Traffic Detection
Detects Zeus C2 communication using HTTP POST requests to URIs containing /gate.php within the first 10 bytes of the URI. Applicable for traffic directed to the server in established sessions (SID:100001).
-	Config File Download Detection
Identifies Zeus downloading configuration files by matching the User-Agent header (MSIE 6.0) and requests for /config.bin, in established connections to the server (SID:100003).
-	Specific Data Pattern in HTTP Traffic
Flags Zeus traffic containing specific byte patterns (DE AD BE EF and FE ED FA CE within 50 bytes) in HTTP data to the server (SID:100007).
-	DNS Query for Known Domain
Detects DNS queries for fpdownload.macromedia.com, a domain linked with Zeus activity (SID:100009).

4.	Execute Suricata with the specified ruleset, then extract and export the Suricata logs along with the system and security logs.
 

  
Splunk Analysis

Name: Abdelrahman Farid Elsaid 	2106145
Basic Investigation 

The first step was to ingest 4 Important Files into Splunk 
1)	Security Events Logs (csv)
2)	System Events Logs (csv)
3)	Suricata Alert Logs (json)
4)	Another Suricata Alert Logs (txt)
The Next Step was to Perform Basic Search Across all files to gather Information
1)	Perform this SPL Query to get the top Source IP 
( index="zeuslogs" | top src_ip )
 

2)	Perform this SPL Query to get the top Destination IP 
( index="zeuslogs" | top dest_ip )
 
3)	Perform this SPL Query to identify IPs generating Significant Outbound Traffic based on bytes
( index="zeuslogs" | stats sum(flow.bytes_toserver) as total_bytes_outbound by src_ip | where total_bytes_outbound > 50000 )
 

4)	Perform this SPL Query to count the number of events between source and destination IPs
( index="zeuslogs" | stats sum(bytes) as total_bytes, count by src_ip, dest_ip )
 


5)	Perform This SPL Query to Retrieve all Logs related to ZeroAcess Malware
( index="zeuslogs" zeroaccess ) 

 

The Next Step is to Co-Relate Security Events with System Events to Detect Suspicious Behavior

1)	Perform this SPL Query to retrieve all events related to security with event ID 1100 related to Shutdown of Logging Service and notice the event timed at 9:22:38 AM 
(index=”seclog” 1100 )
 
The next step is to analyze the system logs in the same timing that we got from the security log that we identified earlier using this SPL Query, and notice this specific Log
(index="syslogs" | sort -_time)
 

So, we can conclude that the Malware Stopped the logging service.

2)	Perform this SPL Query to retrieve all events related to security with event ID 4672 related to Special privileges assigned to new logon and notice this event timed at 11:23:10 PM 
(index="seclog" 4672 | sort _time)
 
The next step is to analyze the system logs in the same timing that we got from the security log that we identified earlier using this SPL Query, and notice this specific Log
 

So, we can conclude that the Malware elevated privileges using SYSTEM and cleaned traces.


3)	Perform this SPL Query to retrieve all events related to security with event ID 4732 related to adding account to security enabled group (administrators) and notice this event timed at 11:23:05 PM 
(index="seclog" 4732 | sort _time) 

 
The next step is to analyze the system logs in the same timing that we got from the security log that we identified earlier using this SPL Query, and notice this specific Log
 

So, we can conclude that the Malware changed the system time to an earlier timestamp to Manipulate logs, evade detection, and alter security controls.

The Last Step is to create Visual Dashboard to track Malicious Activity

The dashboard was built over these 4 SPL Queries:
1)	index="zeuslogs" | top dest_ip  : Top Destination IPs based on events count.
2)	index="zeuslogs" | top src_ip  : Top Source IPs based on events count.
3)	index="zeuslogs" | stats sum(flow.bytes_toserver) as outbound_bytes by src_ip : Calculates the total amount of outbound data sent to servers by each source IPs
4)	index="zeuslogs" | stats sum(flow.bytes_toserver) as outbound_bytes by dest_ip : Calculates the total amount of outbound data sent to each destination IP.
The Dashboard

 

  
Analyzing The Zeus Banking Trojan with Volatility
This report aims to analyze a memory dump of a potentially compromised system using the Volatility 2 Framework to identify active and injected processes related to Zeus and investigate associated network connections. I will utilize the volatility plugins to study the processes, memory strings, memory code injection, and network connections.
Identifying the system
First, we analyze the image information to know what we’re dealing with using the imageinfo module which reveals it’s a windows XP memory dump
Enumerating Processes
•	looking at the processes using python2 vol.py -f zeus2x4.vmem --profile WinXPSP2x86 pslist. We don’t see anything suspicious from the processes listed here as the count and names of the processes look fine.

 
Network connections
When analyzing the network connections using connscan where we get 3 different IP addresses. Scanning each one resulted in only one suspicious IP address 193.43.134.14 hooked to a process with ID 1752.

 

The IP shows malicious activity on virustotal.


 
Malicious Process
Now to check which process was communicating with this IP address by grepping the output of psscan. We can see that the process that made the suspicious network connection is “explorer.exe” of PID1752.

 















Code injection
Nothing about the process is suspicious. The code might be injected into the process. We’ll use malfind plugin to check.
Using python2 vol.py -f zeus2x4.vmem —profile WinXPSP2x86 malfind -p 1752

By looking at the result of the explorer.exe online it shows that this process has MZ header and protection of PAGE_EXECUTE_READWRITE, which means that this memory region is marked as executable, and it can also be both read from and written to. Memory regions shouldn’t be executable and writable at the same time.






We’ll try dumping this process information  










We can get the strings and by getting the sha256 checksum we can look it up on virustotal as follows:

 







We can check the hash on virustotal and see that it actually is malicious.
 

Conclusion:
•	This memory dump is infected contains a malware 
•	Initial connection to the C2 server was made to the IP 193.43.134.14
•	Malware is hooked to the explorer.exe process with ID 1752

 
Zeus Banking Trojan Detection With YARA
•	Objective:
Detect Zeus with YARA Signatures:
o	Write custom YARA rules to detect
Zeus-related patterns in binaries, configuration files, and memory dumps.
o	Scan the infected system and memory dumps
with YARA to identify Zeus artifacts.
•	Steps:
1.	Using Strings to Extract Data from the memory dump file:
 
 

2.	Searching for Suspected Common Strings:
Once the strings are extracted, the next step is to search for suspected common strings or patterns that could indicate suspicious activity. This involves looking for signatures, keywords, or patterns that are indicative of known malicious behavior or functions.
3.	Creating YARA Rules Based on Suspected Functions Calls, Magic Bytes, and Strings:
After identifying suspected strings or patterns, the next step is to create YARA rules to automate the detection of these suspicious behaviors. YARA rules can be based on the following elements:
•	Function calls – If suspicious function calls were detected in the extracted strings, YARA rules can be created to match these function names.
•	Magic bytes – Specific byte sequences that are known to indicate file formats or data structures associated with malware.
•	Strings – Custom strings that match specific patterns found in the extracted strings.
 





4.	Running YARA on the malicious file:
The final step is to run the created YARA rules on the malicious file to check for any matches that would indicate the presence of malicious content. YARA will scan the file, using the created rules, and report any potential indicators of compromise.
 
 



•	Command Flag:
-s: Displays matching strings.
-w: Enables warnings (useful for debugging rules).
-p 32: Sets the maximum process recursion depth to 32. This is helpful when scanning     complex binaries.
5.	Output explanation:
Match 1:
$function_name_KERNEL32_CreateFileA: The name of the matched string in your YARA rule. In this case, it indicates a function call to CreateFileA from the Windows KERNEL32.dll library.
•	CreateFileA: This function is often used in malware to create, open, or manipulate files.
•	CellrotoCrudUntohighCols: This is the actual value or string found at the offset, potentially used in the malicious operation.
Match 2:
$function_name_KERNEL32_FINDFIRSTFILEA: This appears to refer to the name of a Windows API function. Specifically, FindFirstFileA is a function in the KERNEL32.dll library used to find the first file in a directory that matches a given pattern. The "A" at the end typically refers to the ANSI version of the function (as opposed to FindFirstFileW, which would be the wide-character version).
Match 3:
$PE_magic_byte: A string defined in your YARA rule, representing the PE (Portable Executable) file signature.
•	MZ: The magic bytes of a Windows executable, confirming that this file is a PE binary.
Match 4:
$hex_string: The name of the string in the YARA rule, which matches the hex values in the file.
•	43 61 6D 65 56 61 6C 65 57 61 75 6C 65 72: Hexadecimal representation of the ASCII string CameValeWaule.
•	This could be an encoded or obfuscated string used in the malware.





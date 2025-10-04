# Windows IR Checklist
Note the Windows checklist is a work in progress. The original was [posted on my blog](https://mashtitle.com/2025/06/01/incident-response-checklist), but this GitHub Markdown document will now reflect the latest version.

This is a (mostly) Windows event-focused checklist I’ve been working on for reference in SIEMs. It mixes MITRE ATT&CK tactics, Cyber Kill Chain phases, and operational buckets like authentication and detection that are important to defenders. I think this taxonomy (Authentication, Detection, Initial Compromise, Recon/Staging, Credential Theft, Persistence, Privilege Escalation, Lateral Movement, Execution, Defense Evasion, Command and Control, and Data Exfiltration) helps align log sources with investigative workflows.

Unfortunately, there is not an authoritative source for events: Microsoft Learn covers a majority of events described in the list, but it isn't complete. A link is associated with each event, if available.

I'm currently reviewing how to proceed with this project. In time, the humble checklist may be generated from a series of TOML or YAML files with a structure that describes:
1. Event ID
2. Channel
3. Provider
4. Taxonomy
5. Event title
6. Event description
7. Artifacts that may be relevant to IR, with an optional description
8. URL(s) to MS Learn or other resources
9. Tag(s)

The source TOML/YAML files may even form the basis for a site, where folks can sort based on keyword, event ID, taxonomy, etc.

Here are some other resources related to Windows event logs that you may find useful:
[Ultimate Windows Security Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)
[German BSI FOIS Configuration Recommendations for Windows Logging](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Cyber-Security/SiSyPHuS/AP10/Logging_Configuration_Guideline.pdf?__blob=publicationFile&v=5)
[13cube’s Impacket Exec Commands Cheat Sheet](https://cdn.13cubed.com/downloads/impacket_exec_commands_cheat_sheet.pdf)
[JPCERT/CC’s Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet)
[The main Sigma rule repository](https://github.com/SigmaHQ/sigma)
[Yamato Security's Windows Event Log Configuration Guide For DFIR And Threat Hunting](https://github.com/Yamato-Security/EnableWindowsLogSettings)


# Linux IR Checklist
The Linux list is significantly less refined than the Windows checklist. It was built using my notes from Taz Wake's excellent SANS FOR577 course, Linux Incident Response and Threat Hunting, and 13Cubed's similarly excellent Investigating Linux Devices course.

# M365/Azure IR Checklist
This was built using my notes from SANS FOR509, Enterprise Cloud Forensics and Incident Response, and work on XINTRA's APT labs.

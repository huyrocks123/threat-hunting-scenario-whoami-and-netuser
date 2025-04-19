# Threat Hunt Report: Suspicious Use of whoami and net user
- [Scenario Creation](https://github.com/huyrocks123/threat-hunting-scenario-whoami-and-netuser/blob/main/threat-hunting-scenario-whoami-and-netuser-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- whoami, hostname, net user, net localgroup administrators

##  Scenario

IT security analysts have noted multiple short bursts of built-in command-line tool usage across endpoints. These commands, while legitimate for administrative use, are commonly leveraged during the reconnaissance phase of cyber attacks. There were no support tickets justifying this activity, and the patterns appeared during off-hours, which raised suspicion. The goal of this hunt is to determine whether unauthorized users are executing enumeration commands to gather system or user account information.

If suspicious patterns are found, escalate to incident response and notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceProcessEvents`** for use of enumeration commands like whoami, hostname, net user, and net localgroup administrators.
- **Check `DeviceFileEvents`** to detect whether output was redirected to text files (e.g., recon.txt).
- **Look for short intervals between recon commands suggesting a script or manual probing session.

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table

Searched for execution of whoami, hostname, net user, and net localgroup administrators from the Command Prompt or PowerShell.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-huy"
| where ProcessCommandLine has_any ("whoami", "hostname", "net.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

```
<img width="777" alt="Screenshot 2025-04-19 at 7 30 03 PM" src="https://github.com/user-attachments/assets/1136cb7c-6305-4ff9-b6a9-881b59da7968" />

---

### 2. Searched the `DeviceFileEvents` Table

Investigated if the output of recon commands was saved to a text file like recon.txt.

**Query used to locate event:**

```kql
DeviceFileEvents
| where FolderPath contains "Desktop"
| where FileName contains "recon.txt"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType

```
<img width="1461" alt="Screenshot 2025-04-19 at 7 32 02 PM" src="https://github.com/user-attachments/assets/3aa74780-8ebb-4a44-8a3a-4d164fd3b623" />

---

## Chronological Event Timeline 

### 1. Recon command execution started

- **Timestamp:** `2025-04-19T20:43:31.7496528Z`
- **Event:** The user "huy" launched a series of reconnaissance commands including whoami, hostname, net user, and net localgroup administrators using PowerShell. These commands were executed within a short time frame, indicating possible enumeration activity after initial access.
- **Action:** Process creation events for multiple built-in Windows recon commands detected.

### 2. File creation - recon.txt

- **Timestamp:** `2025-04-19T22:49:54.0187491Z`
- **Event:** The user "huy" redirected the output of the whoami command to a text file named recon.txt, which was created on the Desktop. This behavior is often seen during early-stage attacker activity when attempting to gather and store system information.
- **Action:** File creation event detected.
- **File Path:** `C:\Users\huy\Desktop`

---

## Summary

The user huy executed a series of reconnaissance-related commands typically used by adversaries to enumerate users and groups on a system. These commands were run within a short timeframe and the output was saved to a text file named recon.txt on the Desktop. This activity suggests either a deliberate reconnaissance effort or testing of built-in commands in a lab setting.

---

## Response Taken

Since this activity occurred within a test lab and was part of an exercise, no malicious behavior was detected. However, this scenario provides a good baseline to monitor for similar behavior in production environments.

- Created alert rule in MDE for grouped recon commands.

- Flagged the event in the hunt log for future correlation exercises.

---

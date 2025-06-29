# Threat-Hunting-Scenario-Tor

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/t-maka/Threat-Hunting-Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any file containing the string "tor" in its name. The investigation revealed that the user "employee" appears to have downloaded a Tor installer. This action led to several Tor-related files being copied to the desktop, along with the creation of a file named "tor-shopping-list.txt" on the desktop at 2025-06-29T13:59:46.9091113Z. These events began at: 2025-06-29T13:46:06.1907745Z

**Query used to locate the activity:** 


```kql
DeviceFileEvents
| where DeviceName == "labwill-threat-"
| where InitiatingProcessAccountName == "employee"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-06-29T13:46:06.1907745Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![Tor download detected](https://github.com/user-attachments/assets/f2958a59-bf29-4a0a-aa23-42a184af561d)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents for any ProcessCommandLine that contained the string "tor‑browser‑windows‑x86_64‑portable‑14.5.4.exe". Based on the logs returned: On June 29, 2025 at 2:48:50 PM, the device “labwill-threat-” logged that the user “employee” launched a Tor Browser installer from their Downloads folder—specifically "tor‑browser‑windows‑x86_64‑portable‑14.5.4.exe" (SHA‑256: 5035adc9…), running it silently with the /S flag.

**Query used to locate the activity:** 


```kql
DeviceProcessEvents
| where DeviceName == "labwill-threat-"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe  /S"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![Tor silent installation](https://github.com/user-attachments/assets/0e3fe9a4-fb3d-4e6b-9bf5-38ae7ff467c4)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I searched the DeviceProcessEvents table for any indication that the user “employee” actually launched the Tor Browser. The findings show that it was indeed opened at:  2025-06-29T13:49:25.2758855Z.
Several additional instances of firefox.exe (associated with Tor) and tor.exe were launched subsequently.

**Query used to locate the activity**

```kql
DeviceProcessEvents
| where DeviceName == "labwill-threat-"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
```
![Tor browsing activity](https://github.com/user-attachments/assets/3e79a394-7797-4e7d-a210-3c193db12168)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Query the DeviceNetworkEvents table for signs that the Tor browser may have been used to initiate a connection over any known Tor-related ports.
At 2:52 PM on June 29, 2025, an employee on the device “labwill-threat-” successfully established a connection to the IP address 85.215.63.163 over port 9001, using the process tor.exe — indicating that the Tor browser was actively communicating over the Tor network.
**Query used to locate the activity:**

```kql
DeviceNetworkEvents
| where DeviceName == "labwill-threat-"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151", "80", "443")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```


---

## Chronological Event Timeline 

## ⏳ Chronological Timeline of Events

| 🕒 **Timestamp (UTC)**             | 📝 **Event Description**                                                                                             |
|----------------------------------|----------------------------------------------------------------------------------------------------------------------|
| `2025-06-29T13:46:06.1907745`    | ✅ Initial suspicious file events triggered from a file containing `"tor"` in the filename.                          |
| `2025-06-29T13:46 – 13:59`       | 📁 Multiple Tor-related files written to the Desktop, indicating installer unpacking or directory extraction.        |
| `2025-06-29T13:49:25.2758855`    | 🚀 Tor Browser processes (`tor.exe`, `firefox.exe`) launched by user `employee`.                                    |
| `2025-06-29T13:59:46.9091113`    | 🗒️ File `tor-shopping-list.txt` created on the Desktop. File content not analyzed in this hunt.                     |
| `2025-06-29T14:48:50`            | ⚙️ Silent installation of Tor using `tor-browser-windows-x86_64-portable-14.5.4.exe /S` initiated from Downloads.   |
| `2025-06-29T14:52:00`            | 🌐 Outbound network connection by `tor.exe` to IP `85.215.63.163` on **port 9001** — a known Tor relay node.         |
| `2025-06-29T14:52 – onwards`     | 🔁 Ongoing secure connections (port 443) to various endpoints, aligning with anonymized web traffic via Tor.        |


---

## Summary

The user employee on “labwill-threat-” downloaded and silently installed the Tor Browser (tor-browser-windows-x86_64-portable-14.5.4.exe) at `2:48 PM`.

Immediately afterward, multiple instances of `firefox.exe` and `tor.exe` processes were launched, confirming that the browser was opened.

At `2:52 PM`, a successful outbound connection was made using tor.exe to a known Tor network node over port `9001`, validating Tor network activity. Besides, various files related to Tor were found on the user's desktop, including a created file named tor-shopping-list.txt.

These findings confirm installation and usage of the Tor Browser, along with external communications likely routed through the Tor network.


---

## Response Taken

TOR usage was confirmed on the endpoint `labwill-threat-` by user `employee`.The device was isolated and the user's direct manager was notified.

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `June 2025`    | `Tinan Makadjibeye`   |

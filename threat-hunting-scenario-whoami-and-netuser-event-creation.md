# Threat Event (Suspicious Use of whoami and net user)
**Reconnaissance Activity via Built-in Windows Commands**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Open PowerShell or Command Prompt
2. Run the following commands:

whoami
hostname
net user
net localgroup administrators

3. Redirect output to a text file:

whoami > C:\Users\huy\Desktop\recon.txt

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detects the creation of recon.txt if output is saved to file. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detects command-line executions (whoami, net user, etc.)|

---

## Related Queries:
```kql
// Detect reconnaissance commands
DeviceProcessEvents
| where ProcessCommandLine has_any ("whoami", "hostname", "net user", "net localgroup administrators")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Detect recon.txt file creation on Desktop
DeviceFileEvents
| where FolderPath contains "Desktop"
| where FileName contains "recon.txt"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType

```

---

## Created By:
- **Author Name**: Huy Tang
- **Author Contact**: https://www.linkedin.com/in/joshmadakor/](https://www.linkedin.com/in/huy-t-892a51317/
- **Date**: April 19, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `April 19, 2025`  | `Huy Tang`   

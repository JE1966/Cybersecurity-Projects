# Incident Report

## Executive Summary 
On Tuesday, July 30th, 2024 at approximately 2:40 UTC, a Windows system used by user ccollier was infected with STRRAT malware, which promptly established command-and-control communication with an external system to exfiltrate data.

<table>
  <tr>
    <td><b>What happened?</b></td>
    <td>An STRRAT was executed on a machine and started enumerating the system, sending information on local files and folders to an external IP.</td>
  </tr>
  <tr>
    <td><b>Who caused the incident?</b></td>
    <td>The incident was triggered when user ccollier inadvertently downloaded a malicious file. The external IP that was receiving the extracted data (141.98.10.79) likely belongs to a malicious actor attempting to gain sensitive information.</td>
  </tr>
  <tr>
    <td><b>When did the incident occur?</b></td>
    <td>Tuesday, July 30th, 2024, approximately 2:40 UTC.</td>
  </tr>
  <tr>
    <td><b>Where did the incident happen?</b></td>
    <td>A Windows workstation, DESKTOP-SKBR25F, operated by user ccollier.</td>
  </tr>
  <tr>
    <td><b>Why did the incident happen?</b></td>
    <td>Large file transfers from repositories on Github and Maven occurred immediately before data exfiltration. It is likely that the user ccollier was accessing a repository they believed was safe and inadvertently downloaded the malware.</td>
  </tr>
</table>

## Impact

High. The presence of an STRRAT on the compromised system could enable full remote access or credential theft by an attacker. In this case, only non-critical and non-sensitive system and file information were exfiltrated; however, continued operation would incur severe risks.

## Recommendations

- Isolate the affected system ASAP to prevent further data exfiltration.
- Reset the credentials of the affected workstation and all accounts that have accessed it.
- Perform a full analysis of the affected host to check for further signs of compromise in case the affected system served as a pivot point for lateral movement.
- Block all network traffic involving 141.98.10.79.
- Perform threat hunting for similar indicators on other systems on the network.
- Perform user awareness training on safe repository usage and verification of repository sources.

## Indicators of Compromise

- (critical) TCP traffic from the STRRAT to 141.98.10.79:12132 enumerating the host system.
- Large application data transfers from Github (IPs: 140.82.113.3, 185.199.110.133) and Maven (IP: 199.232.196.209) repos shortly before suspicious TCP traffic.
- External IP lookup on ip-api.com between the above application data transfers and suspicious TCP traffic.

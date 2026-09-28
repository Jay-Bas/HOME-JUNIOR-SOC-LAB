# Home SOC Lab Portfolio — Phases 1–8

A hands-on cybersecurity portfolio built on top of an existing home SOC lab (Wazuh SIEM, Suricata IDS, Docker, Ubuntu VM, and a Windows 11 host). Each phase moves from basic vulnerability assessment through to full packet-level analysis, with every finding investigated, verified, and — where needed — remediated.

**Full narrative write-up with findings:** see `Home_SOC_Lab_Portfolio.pdf` in this repo.

**Lab environment:** Ubuntu VM (VirtualBox, host-only network `192.168.100.0/24`), Wazuh 4.9.0 (Docker: manager, indexer, dashboard), Suricata IDS, plus a Windows 11 host machine for Phase 5.

---

## Phase 1 — Vulnerability Assessment & Nmap

| Command | What it does |
|---|---|
| `nmap --version` | Confirms Nmap is installed and shows its version |
| `sudo apt update && sudo apt install nmap -y` | Installs Nmap |
| `ip a` | Lists network interfaces and IP addresses to identify the lab-facing interface |
| `sudo nmap -sV -O 192.168.100.20` | Service/version detection + OS fingerprinting scan against the target |
| `sudo nmap -sV --script ssh2-enum-algos,ssh-auth-methods 192.168.100.20` | Enumerates supported SSH key exchange/encryption algorithms and accepted authentication methods |
| `sudo nmap -sV --script vuln 192.168.100.20` | Runs Nmap's vulnerability-detection script category against detected services |
| `apt-cache policy openssh-client` / `openssh-server` | Compares installed vs. available (candidate) package version to check for a patch |
| `sudo apt update && sudo apt install --only-upgrade openssh-client openssh-server -y` | Upgrades OpenSSH to the latest available version |
| `ssh -V` | Confirms the installed OpenSSH version after upgrade |
| `sudo ufw status` / `sudo ufw status numbered` | Shows current firewall rules, numbered for targeted deletion |
| `sudo ufw allow from 192.168.100.0/24 to any port 22` | Restricts SSH access to the trusted lab subnet only |
| `sudo ufw delete <number>` | Removes a specific firewall rule by its number |
| `sudo ufw enable` | Activates the firewall |
| `ssh-keygen -t ed25519 -C "jayy-lab-key"` | Generates a new SSH key pair for key-based authentication |
| `cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys` | Authorizes the new public key for SSH login |
| `chmod 600 ~/.ssh/authorized_keys` / `chmod 700 ~/.ssh` | Locks down permissions required for SSH key auth to work |
| `sudo nano /etc/ssh/sshd_config` → `PasswordAuthentication no` | Disables password-based SSH login, enforcing key-only auth |
| `sudo systemctl restart ssh` | Applies the new SSH configuration |
| `ssh vboxuser@192.168.100.20` | Live test to confirm key-only login works and password auth is rejected |

**Key finding:** CVE-2026-60002 (OpenSSH client use-after-free, CVSS 9.4) — no vendor patch available at time of assessment. Mitigated via subnet-restricted firewall access and key-only SSH authentication.

---

## Phase 2 — Log Analysis & Security Monitoring

| Command | What it does |
|---|---|
| `ls -la /var/log/` | Lists all available system log sources |
| `sudo tail -50 /var/log/auth.log` | Reviews the most recent authentication log entries |
| `sudo grep -ai "invalid user\|failed password" /var/log/auth.log` | Searches auth.log for failed/invalid login attempts (`-a` forces text mode if grep misreads the file as binary) |
| `sudo tail -30 /var/log/ufw.log` | Reviews recent firewall block/allow activity |
| `sudo grep -i "block" /var/log/ufw.log \| tail -20` | Filters firewall log for blocked connection attempts |
| `arp -a` | Lists currently known devices on the local network (ARP cache) |

**Key finding:** Identified a one-time blocked FTP connection to an unrecognized host; ARP cache had already expired by time of analysis, illustrating the importance of near-real-time log correlation.

---

## Phase 3 — SIEM / SOC Investigation (Wazuh)

| Command | What it does |
|---|---|
| `sudo docker ps` | Confirms the Wazuh manager, indexer, and dashboard containers are running |
| `sudo docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l` | Lists registered Wazuh agents and their connection status |
| `sudo tail -30 /var/ossec/logs/ossec.log` | Reviews Wazuh's own internal operational log |
| `sudo systemctl restart wazuh-agent` | Restarts the Wazuh agent service to force reconnection |
| `sudo grep -i "auth.log" /var/ossec/etc/ossec.conf` | Checks whether auth.log is configured as a monitored log source |
| `sudo nano /var/ossec/etc/ossec.conf` → add `<localfile>` block for `/var/log/auth.log` | Adds the missing log source so SSH/auth activity is actually ingested by Wazuh |
| Dashboard query: `data.alert.signature_id:1000001` | Searches Wazuh/Suricata alerts by signature ID |
| Dashboard query: `data.dest_port:6200` | Checks for traffic on the vsftpd backdoor's known shell port |
| Dashboard query: `agent.name:jayy and location:"/var/log/auth.log"` | Confirms auth.log events are now flowing into Wazuh after the fix |

**Key finding:** Discovered and fixed a major SIEM coverage gap — `/var/log/auth.log` had never been configured as a monitored source, meaning SSH/sudo activity was invisible to Wazuh throughout Phases 1–2. Also investigated a Suricata alert for a known vsftpd 2.3.4 backdoor signature; confirmed outbound-only traffic with no evidence of actual backdoor shell access.

---

## Phase 4 — Incident Response

| Command | What it does |
|---|---|
| `for i in 1 2 3 4 5; do ssh wronguser$i@192.168.100.20; done` | Simulates a rapid brute-force SSH login attempt (5 invalid users) |
| Dashboard query: `agent.name:jayy and rule.level >= 5` | Searches for medium/high-severity alerts related to the simulated attack |
| Dashboard query: `agent.name:jayy and full_log:wronguser` | Searches raw logs for any trace of the brute-force attempt |
| `sudo grep -i wronguser /var/log/auth.log` | Confirms the attack occurred at the OS log level, independent of the SIEM |
| `sudo grep -ai "queue\|drop\|discard\|overflow" /var/ossec/logs/ossec.log` | Checks Wazuh's internal logs for dropped/overflowed event queues |
| `sudo grep -A3 "client_buffer" /var/ossec/etc/ossec.conf` | Checks the configured Wazuh agent buffer/queue size |
| `sudo grep "AllowUsers" /etc/ssh/sshd_config` | Verifies SSH access is still restricted to the intended user |
| `sudo systemctl status ssh wazuh-agent --no-pager` | Confirms both services are healthy post-incident |

**Key finding:** The simulated brute-force was fully blocked by Phase 1's SSH hardening (zero successful logins), but never triggered a Wazuh alert — traced to intermittent agent connectivity and a historical event-queue overflow warning. Documented as an open, honestly-inconclusive detection reliability risk.

---

## Phase 5 — Local Security Audit (Windows 11)

*Adapted from Active Directory Security, since Windows 11 cannot host AD Domain Services — scoped to local account/policy auditing instead.*

| Command | What it does |
|---|---|
| `Get-LocalUser \| Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordExpires` | Lists all local accounts and their status |
| `Get-LocalGroupMember -Group "Administrators"` | Lists everyone with local administrator privileges |
| `Get-LocalUser -Name "Analyst","User1" \| Select-Object Name, PasswordRequired, PasswordLastSet` | Checks specific accounts for password requirements |
| `Disable-LocalUser -Name "User1"` | Disables an account found to have no password requirement |
| `net accounts` | Displays system-wide password and account lockout policy |
| `net accounts /uniquepw:5` | Increases enforced password history from 2 to 5 |
| `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 \| Format-List TimeCreated, Message` | Retrieves full detail on failed logon events (Event ID 4625) |

**Key finding:** Found and disabled an enabled local account (`User1`) with no password required. Strengthened password history policy. Reviewed Security event log failed logons — both explained as benign, self-originated events.

---

## Phase 6 — Threat Hunting

| Command | What it does |
|---|---|
| `ps aux --sort=-%cpu \| head -20` | Lists top CPU-consuming processes, looking for unrecognized names or odd run locations |
| `ps -eo pid,ppid,user,lstart,cmd --sort=-%cpu \| head -20` | Same, with process start times and parent PIDs for deeper context |
| `id dnsmasq` / `getent passwd dnsmasq` | Investigates an unexpected process owner by checking the account's UID and login shell |
| `sudo ss -tulpn \| grep -v 127.0.0.1` | Lists all listening network ports excluding localhost-only services |
| `sudo find / -mmin -60 -type f -not -path "/proc/*" -not -path "/sys/*" -not -path "/var/lib/docker/*" -not -path "/var/log/*"` | Searches for any file modified in the last 60 minutes outside expected noisy paths |

**Key finding:** Investigated Wazuh processes appearing to run under the `dnsmasq` user; confirmed via UID/shell lookup (`nologin` shell, standard low system UID) that this is a benign Docker UID-mapping artifact, not a compromise. Network listeners and recent file activity both came back fully explained — a clean hunt across all three angles.

---

## Phase 7 — Advanced Wireshark Investigation

| Command | What it does |
|---|---|
| `sudo apt install tshark -y` | Installs the command-line Wireshark packet capture tool |
| `sudo apt install telnetd inetutils-inetd -y` | Installs a Telnet server for a deliberate insecure-protocol demonstration |
| `sudo systemctl enable --now telnet.socket` | Enables and starts Telnet via systemd socket activation |
| `sudo ss -tulpn \| grep :23` | Confirms the Telnet service is listening on port 23 |
| `sudo tshark -i lo -w /tmp/phase7_lo.pcap` | Captures live packet traffic on the loopback interface |
| `telnet 192.168.100.20` | Connects to the local Telnet service, generating a real plaintext login session |
| `wireshark /tmp/phase7_lo.pcap` → filter `telnet` → *Follow → TCP Stream* | Opens the capture and reconstructs the full Telnet session to inspect plaintext credentials |
| `passwd` | Changes the account password after it was exposed during the demonstration |
| `sudo systemctl disable --now telnet.socket` / `sudo systemctl stop inetutils-inetd` / `sudo systemctl disable inetutils-inetd` | Fully disables the insecure Telnet service after the demonstration |

**Key finding:** Captured and reconstructed a live Telnet login session, recovering the username and password in cleartext — direct proof of why the Phase 1 SSH key-only hardening matters. Telnet service disabled immediately after.

---

## Phase 8 — Final Capstone

Ties all seven phases into one connected investigation narrative rather than isolated exercises — see the executive summary in `Home_SOC_Lab_Portfolio.pdf` for the full write-up.

**What this project demonstrates:** methodical investigation, verifying findings with evidence rather than assumption, honestly documenting inconclusive results, and closing the loop by remediating what was found — across vulnerability assessment, log analysis, SIEM operations, incident response, local security auditing, threat hunting, and packet analysis.

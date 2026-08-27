# SOC Analyst Interview Prep Guide

> รวมสรุปหัวข้อสำหรับเตรียมสัมภาษณ์ SOC Analyst — เขียนโดยอ้างอิงประสบการณ์ IT Manager/Security ของ Virunpon (ISO 27001, Fortinet NSE 1-3, Wazuh lab บน AWS)

---

## สารบัญ
1. [SOC Fundamentals & Analyst Roles](#1-soc-fundamentals--analyst-roles)
2. [Alert Triage & Investigation](#2-alert-triage--investigation)
3. [Incident Response](#3-incident-response)
4. [Networking Fundamentals](#4-networking-fundamentals)
5. [Network Security](#5-network-security)
6. [SIEM & Log Analysis](#6-siem--log-analysis)
7. [EDR & Endpoint Security](#7-edr--endpoint-security)
8. [Email & Phishing Security](#8-email--phishing-security)
9. [Active Directory Security](#9-active-directory-security)
10. [Vulnerability Management](#10-vulnerability-management)
11. [Threat Intelligence](#11-threat-intelligence)
12. [MITRE ATT&CK](#12-mitre-attck)
13. [Security Monitoring & Detection](#13-security-monitoring--detection)
14. [Practical Investigation Scenarios](#14-practical-investigation-scenarios)
15. [Common SOC Interview Questions](#15-common-soc-interview-questions)

---

## 1. SOC Fundamentals & Analyst Roles

**SOC (Security Operations Center)** คือทีม/ศูนย์กลางที่ทำหน้าที่เฝ้าระวัง ตรวจจับ วิเคราะห์ และตอบสนองต่อภัยคุกคามไซเบอร์แบบต่อเนื่อง (มักเป็น 24/7)

### หน้าที่หลัก 5 ข้อ
1. **Monitor** – เฝ้าดู alert/log จากระบบต่างๆ
2. **Detect** – ตรวจจับพฤติกรรมผิดปกติ
3. **Investigate** – วิเคราะห์ True Positive vs False Positive
4. **Respond** – isolate เครื่อง, block IP, escalate
5. **Report** – สรุปเหตุการณ์และปรับปรุง process

### SOC Tiers
| Tier | บทบาท | งานหลัก |
|------|--------|---------|
| Tier 1 (Triage) | จุดแรกรับ alert | คัดกรอง alert, ปิด false positive, ส่งต่อเคสสงสัย |
| Tier 2 (Investigator) | วิเคราะห์เชิงลึก | correlate log หลายแหล่ง, ยืนยัน incident |
| Tier 3 (Threat Hunter/IR) | ผู้เชี่ยวชาญ | threat hunting เชิงรุก, forensics, ปรับ detection rule |
| SOC Manager | บริหารทีม | KPI, process, รายงานผู้บริหาร |

### โมเดล SOC ที่พบบ่อย
- **In-house SOC** – ทีมภายในองค์กรเอง
- **MSSP (Managed Security Service Provider)** – outsource ให้บริษัทภายนอก
- **Hybrid SOC** – ผสมทั้งสองแบบ
- **Virtual SOC** – ทีมกระจายตัว ไม่มี physical war room

---

## 2. Alert Triage & Investigation

### หลักการ Triage
เมื่อ alert เข้ามา ต้องตอบคำถาม 4 ข้อให้ได้เร็วที่สุด:
1. **What happened?** – เกิดอะไรขึ้น (event type)
2. **Where?** – host/user/segment ไหน
3. **How severe?** – กระทบระบบสำคัญหรือไม่
4. **Is it real?** – True Positive, False Positive, หรือ Benign True Positive (จริงแต่ไม่เป็นภัย)

### Priority Matrix (Impact x Urgency)
- Critical: ระบบ production/ข้อมูลสำคัญถูกกระทบ + กำลังเกิดขึ้น
- High: กระทบระบบสำคัญ แต่ยังควบคุมได้
- Medium: กระทบ scope จำกัด
- Low: ทดสอบ/สแกนทั่วไปที่ไม่มีผลกระทบจริง

### ขั้นตอน Investigation ทั่วไป
1. อ่าน alert detail (source, destination, timestamp, rule ที่ trigger)
2. ตรวจ log ที่เกี่ยวข้อง (correlate ข้ามระบบ: firewall, EDR, SIEM)
3. เช็ค reputation ของ IP/domain/hash (VirusTotal, AbuseIPDB)
4. ประเมิน scope – กระทบกี่เครื่อง/user
5. ตัดสินใจ: escalate, contain, หรือ close as false positive
6. เขียน documentation ทุกขั้นตอน (สำคัญมากสำหรับ audit trail)

### False Positive vs True Positive vs False Negative
- **False Positive**: ระบบแจ้งเตือนแต่ไม่ใช่ภัยจริง
- **True Positive**: แจ้งเตือนถูกต้อง เป็นภัยจริง
- **False Negative**: มีภัยจริงแต่ระบบไม่แจ้งเตือน (อันตรายที่สุด)

---

## 3. Incident Response

### NIST Incident Response Lifecycle (มาตรฐานที่มักถูกถามในสัมภาษณ์)
1. **Preparation** – เตรียม tool, playbook, training
2. **Detection & Analysis** – ตรวจพบและวิเคราะห์เหตุการณ์
3. **Containment** – จำกัดความเสียหาย (short-term: isolate เครื่อง / long-term: patch, rebuild)
4. **Eradication** – กำจัดสาเหตุ (มัลแวร์, backdoor, account ที่ถูกยึด)
5. **Recovery** – นำระบบกลับมาใช้งานปกติ พร้อม monitor เพิ่มเติม
6. **Lessons Learned** – post-incident review, ปรับปรุง process

### Containment Strategy
- **Short-term containment**: ตัดเครือข่าย, disable account ทันที เพื่อหยุดความเสียหาย
- **Long-term containment**: patch ช่องโหว่, เปลี่ยนรหัสผ่านทั้งระบบ, เพิ่ม monitoring ก่อน rebuild

### เชื่อมกับประสบการณ์ของคุณ
คุณมีเคส DR site down / DDoS ที่เคยฝึก STAR ไว้แล้ว — ใช้โครงสร้าง NIST lifecycle นี้มาอธิบายเป็นขั้นตอนได้เลย จะทำให้คำตอบมีโครงสร้างและน่าเชื่อถือมากขึ้น

---

## 4. Networking Fundamentals

### OSI Model (7 Layers) — ต้องท่องให้ขึ้นใจ
| Layer | ชื่อ | ตัวอย่าง |
|-------|------|----------|
| 7 | Application | HTTP, DNS, FTP |
| 6 | Presentation | SSL/TLS encryption |
| 5 | Session | session establishment |
| 4 | Transport | TCP, UDP |
| 3 | Network | IP, routing |
| 2 | Data Link | MAC address, switch |
| 1 | Physical | สายสัญญาณ, สัญญาณไฟฟ้า |

### TCP vs UDP
- **TCP**: connection-oriented, มี 3-way handshake (SYN, SYN-ACK, ACK), reliable, ใช้กับ HTTP/HTTPS, SSH
- **UDP**: connectionless, เร็วกว่าแต่ไม่รับประกันการส่งถึง, ใช้กับ DNS, streaming, VoIP

### Protocol สำคัญที่ต้องรู้
- **DNS** (port 53) – แปลงชื่อโดเมนเป็น IP
- **DHCP** (port 67/68) – แจก IP อัตโนมัติ
- **HTTP/HTTPS** (port 80/443) – web traffic
- **SSH** (port 22) – remote access แบบเข้ารหัส
- **RDP** (port 3389) – remote desktop, เป้าหมายยอดฮิตของการโจมตี
- **SMB** (port 445) – file sharing, ใช้ใน lateral movement บ่อย

### แนวคิดสำคัญ
- Subnetting/CIDR, NAT, VLAN segmentation, routing table เบื้องต้น

---

## 5. Network Security

### อุปกรณ์/แนวคิดหลัก
- **Firewall** – กรอง traffic ตาม rule (คุณมีประสบการณ์ Fortinet/SonicWall อยู่แล้ว ใช้พูดได้เลย)
- **IDS vs IPS**
  - IDS (Intrusion Detection System): ตรวจจับแล้ว "แจ้งเตือน" เท่านั้น
  - IPS (Intrusion Prevention System): ตรวจจับแล้ว "บล็อก" ทันที
- **VPN** – เข้ารหัสการเชื่อมต่อระยะไกล
- **Network Segmentation** – แบ่ง zone (DMZ, internal, guest) เพื่อจำกัด lateral movement
- **Zero Trust** – "never trust, always verify" ไม่เชื่อ traffic แม้จะอยู่ใน internal network

### การโจมตีเครือข่ายที่พบบ่อย
- **DDoS** – ทำให้ระบบล่มด้วย traffic จำนวนมาก
- **Man-in-the-Middle (MITM)** – ดักฟัง/แก้ไข traffic ระหว่างสองฝ่าย
- **ARP Spoofing** – ปลอมแปลง MAC address เพื่อดัก traffic ใน local network
- **Port Scanning** – สแกนหาพอร์ตเปิดก่อนโจมตี (มักเป็นสัญญาณ recon ก่อน incident)

---

## 6. SIEM & Log Analysis

### SIEM คืออะไร
Security Information and Event Management – รวบรวม log จากหลายแหล่ง (firewall, server, endpoint, application) มา correlate และสร้าง alert แบบรวมศูนย์

### ตัวอย่าง SIEM ที่นิยม
Splunk, IBM QRadar, Microsoft Sentinel, Elastic (ELK), และ **Wazuh** (ที่คุณกำลังทำ lab อยู่ — เป็น open-source SIEM/XDR ที่ใช้ได้ทั้ง log analysis และ endpoint monitoring)

### Log Source สำคัญที่ SOC ต้องดู
- Firewall logs
- Windows Event Logs (Security, System) – โดยเฉพาะ Event ID 4624 (logon สำเร็จ), 4625 (logon ล้มเหลว), 4688 (process creation)
- Authentication logs (AD, VPN)
- DNS logs – ตรวจจับ C2 communication หรือ DGA domain
- Web/Proxy logs

### แนวคิด Correlation Rule
การตั้ง rule เพื่อจับ pattern เช่น "5 failed login ภายใน 1 นาทีจาก IP เดียวกัน = alert brute force" — ตรงกับ test case ที่คุณกำลังทำใน Wazuh lab (failed SSH login) พอดี

### Log Retention
ควรเก็บ log อย่างน้อย 90 วัน–1 ปี ตามนโยบายองค์กร/กฎหมาย (ที่ไทยมีประเด็น PDPA และ พ.ร.บ.คอมพิวเตอร์ที่กำหนดการเก็บ log ผู้ให้บริการ)

---

## 7. EDR & Endpoint Security

### EDR คืออะไร
Endpoint Detection and Response – ซอฟต์แวร์ที่ติดตั้งบนเครื่อง endpoint เพื่อเฝ้าดูพฤติกรรม process, file, registry แบบ real-time และตอบสนองได้ (isolate, kill process)

### ความแตกต่าง: Antivirus vs EDR vs XDR
- **Antivirus (AV)**: signature-based, จับมัลแวร์ที่รู้จักแล้ว
- **EDR**: behavior-based, จับ pattern ผิดปกติ, มี response capability
- **XDR (Extended Detection and Response)**: ขยายจาก EDR ให้ครอบคลุมหลาย layer (network, email, cloud) ในแพลตฟอร์มเดียว

### สัญญาณที่ EDR มักจับได้
- Process injection, LOLBins (Living-off-the-Land Binaries เช่น powershell.exe, certutil.exe ถูกใช้ในทางที่ผิด)
- Unusual parent-child process (เช่น Word เปิด cmd.exe)
- Persistence mechanism (scheduled task, registry run key)

### เชื่อมกับประสบการณ์
คุณใช้ NinjaOne สำหรับ patch management อยู่แล้ว — อธิบายได้ว่า patching เป็นส่วนหนึ่งของ endpoint hygiene ที่ช่วยลด attack surface ก่อนที่ EDR จะต้องเข้ามาจับ

---

## 8. Email & Phishing Security

### ประเภทของ Phishing
- **Phishing** ทั่วไป – ส่งอีเมลหลอกจำนวนมาก
- **Spear Phishing** – เจาะจงเป้าหมายรายบุคคล
- **Whaling** – เจาะจงผู้บริหารระดับสูง
- **Business Email Compromise (BEC)** – ปลอมเป็นผู้บริหาร/คู่ค้าเพื่อหลอกโอนเงิน
- **Smishing / Vishing** – phishing ผ่าน SMS / โทรศัพท์

### วิธีตรวจสอบอีเมลต้องสงสัย (สิ่งที่ SOC Analyst ต้องทำได้)
1. ตรวจ **header** – Return-Path, Received chain, IP ต้นทาง
2. ตรวจ **SPF, DKIM, DMARC** – ป้องกันการปลอมแปลง sender
   - SPF: ระบุ IP ที่อนุญาตให้ส่งอีเมลแทนโดเมน
   - DKIM: ลายเซ็นดิจิทัลยืนยันว่าอีเมลไม่ถูกแก้ไข
   - DMARC: กำหนดนโยบายเมื่อ SPF/DKIM ล้มเหลว (quarantine/reject)
3. ตรวจลิงก์/attachment ด้วย sandbox หรือ VirusTotal
4. เช็ค urgency/social engineering pattern ในเนื้อหา

### Indicators of Compromise (IOC) จาก phishing
IP/domain ปลายทาง, file hash ของ attachment, URL ที่ปลอมแปลง

---

## 9. Active Directory Security

### แนวคิดพื้นฐาน
AD เป็นศูนย์กลาง identity/authentication ขององค์กร — เป็นเป้าหมายอันดับต้นๆ ที่ผู้โจมตีต้องการยึดครอง (Domain Admin = ควบคุมทั้งองค์กร)

### การโจมตี AD ที่พบบ่อย (มักถูกถามในสัมภาษณ์)
- **Pass-the-Hash** – ใช้ hash รหัสผ่านโดยไม่ต้อง crack เพื่อ authenticate
- **Kerberoasting** – ขอ service ticket แล้วนำไป crack แบบ offline เพื่อได้รหัสผ่าน service account
- **Golden Ticket / Silver Ticket** – ปลอมแปลง Kerberos ticket เพื่อเข้าถึงระบบโดยไม่ต้องรู้รหัสผ่านจริง
- **Brute Force / Password Spraying** – ลองรหัสผ่านทั่วไปกับหลาย account เพื่อเลี่ยงการ lockout
- **Lateral Movement** – ใช้ account/credential ที่ยึดได้เพื่อขยับไปเครื่องอื่นในองค์กร

### Best Practice ที่ SOC ควร monitor
- Failed login attempts ผิดปกติ
- การสร้าง account ใหม่/เพิ่มสิทธิ์ Domain Admin กะทันหัน
- Login นอกเวลาทำการหรือจาก location ผิดปกติ
- Event ID 4768/4769 (Kerberos ticket request) ที่ผิดปกติ

---

## 10. Vulnerability Management

### วงจร Vulnerability Management
1. **Identify** – สแกนหาช่องโหว่ (Nessus, Qualys, OpenVAS)
2. **Prioritize** – ใช้ **CVSS Score** (0-10) ประเมินความรุนแรง ร่วมกับบริบทองค์กร (asset สำคัญแค่ไหน)
3. **Remediate** – patch, config change, หรือ compensating control
4. **Verify** – สแกนซ้ำเพื่อยืนยันว่าแก้แล้วจริง
5. **Report** – ติดตาม SLA การแก้ไขตามระดับความรุนแรง

### CVSS Severity Range
- Critical: 9.0-10.0
- High: 7.0-8.9
- Medium: 4.0-6.9
- Low: 0.1-3.9

### แนวคิดสำคัญ
- **Patch Management** vs **Vulnerability Scanning** – scan หาปัญหา, patch คือการแก้ปัญหา
- **Zero-day vulnerability** – ช่องโหว่ที่ยังไม่มี patch ณ วันที่ถูกค้นพบ/ใช้โจมตี
- เชื่อมกับ NinjaOne ที่คุณใช้ patch management อยู่แล้ว — พูดได้ว่าคุณเข้าใจ workflow ตั้งแต่ scan ถึง patch จริง

---

## 11. Threat Intelligence

### ระดับของ Threat Intelligence
- **Strategic** – ภาพรวมสำหรับผู้บริหาร (เทรนด์ภัยคุกคามระดับอุตสาหกรรม)
- **Tactical** – TTP (Tactics, Techniques, Procedures) ของผู้โจมตี
- **Operational** – รายละเอียด campaign/attack ที่กำลังเกิด
- **Technical** – IOC ที่ใช้ได้ทันที (IP, hash, domain)

### Indicators of Compromise (IOC) ทั่วไป
IP address, domain name, file hash (MD5/SHA256), email address, URL ที่เป็นอันตราย

### แหล่งข้อมูล Threat Intel ที่ควรรู้จัก
VirusTotal, AbuseIPDB, AlienVault OTX, MISP (platform แชร์ threat intel แบบ community/องค์กร)

### วิธีใช้ในงาน SOC จริง
เมื่อพบ IOC ใหม่จาก incident ให้เพิ่มเข้า watchlist/blocklist เพื่อป้องกันการโจมตีซ้ำ และแชร์ให้ทีมอื่นหรือ community ที่เกี่ยวข้อง

---

## 12. MITRE ATT&CK

### คืออะไร
Framework ที่รวบรวม **Tactics (เป้าหมาย)** และ **Techniques (วิธีการ)** ที่ผู้โจมตีใช้จริง จัดเป็นตาราง (Matrix) ให้ SOC ใช้อ้างอิงในการ detect และ investigate

### Tactics หลัก (ลำดับคร่าวๆ ของการโจมตี)
1. Reconnaissance – สอดแนมเป้าหมาย
2. Initial Access – เจาะเข้าระบบครั้งแรก (phishing, exploit)
3. Execution – รันโค้ดอันตราย
4. Persistence – ฝังตัวให้กลับเข้ามาได้อีก
5. Privilege Escalation – ยกระดับสิทธิ์
6. Defense Evasion – หลบเลี่ยงการตรวจจับ
7. Credential Access – ขโมย credential
8. Lateral Movement – ขยับไปเครื่องอื่น
9. Collection – รวบรวมข้อมูลเป้าหมาย
10. Exfiltration – ขโมยข้อมูลออกนอกองค์กร
11. Impact – สร้างความเสียหาย (ransomware, wipe data)

### วิธีใช้ในสัมภาษณ์
เวลาอธิบาย incident scenario ใดๆ ให้ลองแมปเข้ากับ Tactic ของ MITRE ATT&CK (เช่น "นี่คือ Initial Access ผ่าน phishing ตามด้วย Execution ของ malicious macro") จะทำให้คำตอบดูเป็นมืออาชีพและมีมาตรฐานอ้างอิงชัดเจน

---

## 13. Security Monitoring & Detection

### แนวคิดหลัก
- **Baseline** – ต้องรู้ว่า "ปกติ" หน้าตาเป็นอย่างไรก่อน ถึงจะเห็นความผิดปกติ
- **Signature-based Detection** – จับตาม pattern ที่รู้จักแล้ว (เร็วแต่พลาด zero-day)
- **Anomaly-based Detection** – จับพฤติกรรมที่เบี่ยงจาก baseline (จับของใหม่ได้ แต่ false positive สูงกว่า)
- **Behavioral Analytics (UEBA)** – วิเคราะห์พฤติกรรม user/entity เพื่อจับ insider threat หรือ compromised account

### Key Metrics ของ SOC (มักถูกถามเรื่อง KPI)
- **MTTD (Mean Time to Detect)** – เวลาเฉลี่ยในการตรวจพบภัย
- **MTTR (Mean Time to Respond/Resolve)** – เวลาเฉลี่ยในการตอบสนอง/แก้ไข
- **Alert Volume vs Analyst Capacity** – ป้องกัน alert fatigue

---

## 14. Practical Investigation Scenarios

ตัวอย่างสถานการณ์ที่มักใช้ทดสอบใน interview (ลองฝึกตอบแบบ STAR หรือ step-by-step):

### Scenario 1: Suspicious Login
> "พนักงานล็อกอินสำเร็จจากประเทศที่ไม่เคยเข้าใช้งานมาก่อน เวลาตี 3 คุณจะทำอย่างไร?"
- เช็ค login history ปกติของ user นี้
- เช็คว่ามี VPN/travel notification หรือไม่
- เช็คว่ามี MFA หรือไม่ และ MFA ผ่านหรือไม่
- ถ้าน่าสงสัย: บังคับ reset password, revoke session, แจ้ง user ยืนยันตัวตน

### Scenario 2: Ransomware Alert
> "EDR แจ้งเตือนว่าเครื่องหนึ่งกำลังเข้ารหัสไฟล์จำนวนมาก คุณทำอะไรก่อน?"
- Isolate เครื่องออกจากเครือข่ายทันที (short-term containment)
- ระบุ scope – มีเครื่องอื่นติดด้วยหรือไม่ (เช็ค lateral movement)
- เก็บหลักฐาน (memory dump, log) ก่อน wipe/rebuild
- แจ้ง IR team และผู้บริหารตาม escalation path
- ตรวจสอบ backup ว่าใช้กู้คืนได้หรือไม่

### Scenario 3: Phishing Reported by User
> "พนักงานแจ้งว่าคลิกลิงก์ในอีเมลแล้วกรอกรหัสผ่านไป คุณจะทำอย่างไร?"
- Reset password และ revoke active session ทันที
- เช็คว่า account ถูกใช้ทำอะไรไปแล้วบ้าง (mailbox rule แปลกๆ, การส่งอีเมลออกผิดปกติ)
- Block URL/sender ใน email gateway
- แจ้งเตือนพนักงานคนอื่นที่อาจได้รับอีเมลเดียวกัน

### Scenario 4: Unusual Outbound Traffic
> "SIEM แจ้งว่ามี traffic ปริมาณมากออกไปยัง IP ต่างประเทศตอนดึกจากเซิร์ฟเวอร์ภายใน"
- เช็คว่า IP ปลายทางมี reputation แย่หรือไม่ (VirusTotal/AbuseIPDB)
- เช็คว่าเป็น data exfiltration หรือ legitimate backup/sync job
- ตรวจ process ที่สร้าง traffic นี้บนเซิร์ฟเวอร์
- ถ้าน่าสงสัย: block ที่ firewall, isolate เซิร์ฟเวอร์, เริ่ม incident response

---

## 15. Common SOC Interview Questions

### คำถามความรู้ทั่วไป
- SOC Tier 1, 2, 3 ต่างกันอย่างไร?
- อธิบายความแตกต่างระหว่าง IDS กับ IPS
- SIEM ทำงานอย่างไร และทำไมองค์กรถึงต้องมี?
- อธิบาย incident response lifecycle (NIST)
- MITRE ATT&CK คืออะไร และใช้งานอย่างไร?
- SPF, DKIM, DMARC ต่างกันอย่างไร?
- อธิบายความแตกต่างระหว่าง vulnerability กับ threat กับ risk

### คำถามเชิงสถานการณ์ (Behavioral/Scenario)
- เล่าครั้งที่คุณต้องจัดลำดับความสำคัญของ alert หลายตัวพร้อมกัน
- ถ้าคุณเจอ alert ที่ไม่แน่ใจว่าเป็นภัยจริงหรือไม่ คุณจะทำอย่างไร
- เล่าประสบการณ์ที่คุณต้อง escalate เคสให้ทีมอื่น
- ถ้า SIEM ส่ง alert จำนวนมากเกินจะดูทัน (alert fatigue) คุณจะจัดการอย่างไร

### คำถามที่เหมาะกับ background การเป็น IT Manager ของคุณ
- คุณเคยบริหารทีมมาก่อน คิดว่าอะไรคือความท้าทายที่สุดในการทำงานเป็น SOC Analyst หลังจากเคยเป็นผู้บริหาร?
- ประสบการณ์ ISO 27001 ช่วยให้คุณเข้าใจ SOC process อย่างไร?
- คุณจะนำประสบการณ์ patch management (NinjaOne) มาปรับใช้กับงาน vulnerability management ของ SOC อย่างไร?

---

## แนวทางฝึกฝนต่อ (แนะนำ)
1. ทำให้ Wazuh lab ของคุณครบ flow: จำลอง brute-force SSH → ดู alert ขึ้นจริง → เขียนสรุป investigation แบบที่ SOC Analyst ทำจริง เก็บเป็นตัวอย่างเล่าตอนสัมภาษณ์
2. ลองตอบ Scenario ในหัวข้อ 14 แบบพูดออกเสียง (mock interview) จับเวลา 2-3 นาทีต่อคำถาม
3. ทบทวน MITRE ATT&CK Matrix คร่าวๆ 1 รอบ (ไม่ต้องจำทุก technique แค่เข้าใจ 11 tactics และยกตัวอย่างได้)

---
*จัดทำโดย Claude สำหรับการเตรียมสัมภาษณ์ SOC Analyst — อัปเดตล่าสุด 27 ส.ค. 2026*

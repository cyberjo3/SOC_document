# SOC Analyst Interview Prep Guide

> รวมสรุปหัวข้อสำหรับเตรียมสัมภาษณ์ SOC Analyst — เขียนโดยอ้างอิงประสบการณ์ IT Manager/Security ของ Virunpon (ISO 27001, Fortinet NSE 1-3, Wazuh lab บน AWS)

---

## สารบัญ
1. [SOC Fundamentals & Analyst Roles](#1-soc-fundamentals--analyst-roles)
2. [Alert Triage & Investigation](#2-alert-triage--investigation)
3. [Incident Response](#3-incident-response)
4. [Networking Fundamentals](#4-networking-fundamentals)
5. [Network Security](#5-network-security)
6. [SIEM & Log Analysis (+ Splunk)](#6-siem--log-analysis--splunk)
7. [EDR & Endpoint Security](#7-edr--endpoint-security)
8. [Web Proxy Fundamentals](#8-web-proxy-fundamentals)
9. [Email & Phishing Security](#9-email--phishing-security)
10. [Active Directory Security](#10-active-directory-security)
11. [Vulnerability Management](#11-vulnerability-management)
12. [Threat Intelligence](#12-threat-intelligence)
13. [MITRE ATT&CK](#13-mitre-attck)
14. [Security Monitoring & Detection](#14-security-monitoring--detection)
15. [Practical Investigation Scenarios](#15-practical-investigation-scenarios)
16. [Common SOC Interview Questions](#16-common-soc-interview-questions)

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
| Tier 2 (Investigator) | วิเคราะห์เชิงลึก | correlate log หลายแหล่ง, ยืนยัน incident, threat hunting เบื้องต้น |
| Tier 3 (Threat Hunter/IR) | ผู้เชี่ยวชาญ | threat hunting เชิงรุก, forensics, ปรับ detection rule, เป็นหัวหน้าทีม IR |
| SOC Manager | บริหารทีม | KPI, process, รายงานผู้บริหาร |

### โมเดล SOC ที่พบบ่อย
- **In-house SOC** – ทีมภายในองค์กรเอง
- **MSSP (Managed Security Service Provider)** – outsource ให้บริษัทภายนอก
- **Hybrid SOC** – ผสมทั้งสองแบบ
- **Virtual SOC** – ทีมกระจายตัว ไม่มี physical war room

### Alert vs Incident (จุดที่มักสับสน)
- **Alert**: การแจ้งเตือนที่เครื่องมือ (SIEM, EDR, IDS) สร้างขึ้นเมื่อพบสิ่งน่าสงสัย — ยังไม่ยืนยันว่าเป็นภัยจริง
- **Incident**: เหตุการณ์ที่ยืนยันแล้วว่าสร้างความเสียหาย (หรือมีโอกาสสร้างความเสียหาย) ต่อองค์กร และต้องมีการตอบสนอง

*(หมายเหตุ: ถ้าอยากได้ diagram ประกอบหัวข้อนี้ เช่น funnel การจัดลำดับความสำคัญของ alert หรือ flow "Monitor → Detect → Investigate → Respond → Review" บอกได้เลย ผมวาด SVG ให้ใหม่แบบไม่ติดลิขสิทธิ์ได้)*

---

## 2. Alert Triage & Investigation

### หลักการ Triage
เมื่อ alert เข้ามา ต้องตอบคำถาม 4 ข้อให้ได้เร็วที่สุด:
1. **What happened?** – เกิดอะไรขึ้น (event type)
2. **Where?** – host/user/segment ไหน
3. **How severe?** – กระทบระบบสำคัญหรือไม่
4. **Is it real?** – True Positive, False Positive, หรือ Benign True Positive (จริงแต่ไม่เป็นภัย)

### ปัจจัยที่ใช้จัดลำดับความสำคัญของ alert
- Asset Criticality (ระบบสำคัญแค่ไหน)
- User/Account Importance (บัญชีผู้บริหารหรือบัญชีทั่วไป)
- Attack Type & Tactics (โจมตีแบบไหน รุนแรงแค่ไหน)
- Potential Impact (ผลกระทบที่อาจเกิด)
- Confidence Level (มั่นใจแค่ไหนว่าเป็นภัยจริง)
- Business Context (บริบททางธุรกิจ ณ ขณะนั้น)

### ขั้นตอน Investigation ทั่วไป (7 ขั้นตอน)
1. **Alert Received** – alert ถูกสร้างโดยเครื่องมือ (SIEM, EDR, IDS)
2. **Triage** – อ่าน alert detail และรวบรวมข้อมูลเบื้องต้น
3. **Investigation** – เจาะลึก log, endpoint, network และแหล่งข้อมูลอื่น
4. **Validation** – ตัดสินว่าเป็น True Positive หรือ False Positive
5. **Response/Containment** – ดำเนินการควบคุมภัยถ้ายืนยันว่าจริง
6. **Escalation/Resolution** – ส่งต่อให้ Tier 2/3 หรือปิดเคส
7. **Documentation** – บันทึกทุกอย่างเพื่อใช้อ้างอิงและรายงาน

### ข้อมูลสำคัญที่ควรเก็บก่อน escalate alert
Alert/Rule Name, Timestamp, Source IP, Destination IP, Username, Hostname, Process Name, File/Hash, URL/Domain, Port/Protocol, Log Source, Severity, Evidence Collected, Actions Taken

### False Positive vs True Positive vs False Negative
- **False Positive**: ระบบแจ้งเตือนแต่ไม่ใช่ภัยจริง — มักเกิดจาก rule ที่ sensitive เกินไป, กิจกรรม admin ปกติ, หรือ contextual data ไม่ครบ
- **True Positive**: แจ้งเตือนถูกต้อง เป็นภัยจริง — ยืนยันได้ด้วยการเช็ค log หลายแหล่ง, validate IOC (IP/Domain/Hash), correlate เหตุการณ์, เช็ค threat intelligence
- **False Negative**: มีภัยจริงแต่ระบบไม่แจ้งเตือน (อันตรายที่สุด)

### การจัดการ alert หลายตัวจากกิจกรรมเดียวกัน
- จัดกลุ่ม alert ที่คล้ายกันเพื่อลด noise
- หา root cause และจุดเริ่มต้นของเหตุการณ์
- โฟกัสที่ alert แรกสุดในไทม์ไลน์
- สร้าง incident เดียวแล้วผูก alert ที่เกี่ยวข้องเข้าด้วยกัน
- ติดตามกิจกรรมที่เกี่ยวข้องต่อเนื่อง

---

## 3. Incident Response

### NIST Incident Response Lifecycle (มาตรฐานที่มักถูกถามในสัมภาษณ์)
1. **Preparation** – วางแผน ฝึกอบรม สร้าง playbook เตรียมทรัพยากร
2. **Detection & Analysis** – ตรวจพบและวิเคราะห์เหตุการณ์
3. **Containment** – หยุดภัยไม่ให้สร้างความเสียหายเพิ่ม (short-term/long-term)
4. **Eradication** – กำจัดสาเหตุและ artifact อันตรายทั้งหมด
5. **Recovery** – นำระบบกลับมาใช้งานปกติ พร้อม monitor เพิ่มเติม
6. **Lessons Learned** – ทบทวนเหตุการณ์และปรับปรุง process

### Containment vs Eradication (จุดที่มักสับสน)
- **Containment (short-term)**: การกระทำทันทีเพื่อหยุดภัยไม่ให้ลุกลามหรือสร้างความเสียหายเพิ่ม เช่น ตัดเครือข่าย, disable account
- **Eradication (long-term)**: การกำจัด root cause และ malicious component ทั้งหมดออกจากระบบ เช่น ลบมัลแวร์, ปิดช่องโหว่, เปลี่ยนรหัสผ่านทั้งระบบ

### หลังยืนยันว่าเป็น incident จริง ควรทำอะไรบ้าง
1. ทำความเข้าใจ scope และผลกระทบ
2. Contain ภัยทันที
3. เก็บหลักฐาน (log, files, memory)
4. สืบสวนหา root cause
5. กำจัดภัยให้หมด
6. Recovery ระบบและ monitor ต่อ
7. เอกสารทุกอย่างและแชร์รายงาน

### Incident Severity แบ่งตามระดับ (Impact)
| ระดับ | ลักษณะ |
|-------|--------|
| Critical | ระบบ business หยุดทำงาน, data loss, ransomware, breach |
| High | privilege abuse, malware, กระทบหลายระบบ |
| Medium | กิจกรรมน่าสงสัยที่กระทบจำกัด, policy violation |
| Low | ผลกระทบน้อยมาก, alert เชิง informational |

### ทำไม documentation ถึงสำคัญระหว่าง IR
สร้างไทม์ไลน์ที่ชัดเจน, ช่วยเรื่องการสื่อสาร/escalation, รองรับข้อกำหนดกฎหมาย/compliance, ใช้อ้างอิงสำหรับการสืบสวนครั้งต่อไป, และช่วยปรับปรุงกระบวนการตอบสนองในอนาคต

### เครื่องมือที่ช่วย SOC Analyst ระหว่าง Incident Response
SIEM (วิเคราะห์ log/สร้าง alert), EDR (เฝ้าดู endpoint/process/threat), OS Tools (คำสั่งระบบตรวจสอบ log), Threat Intelligence (เช็ค reputation ของ IP/domain/hash), Ticketing System (ติดตามงานและการสื่อสาร)

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

### เกิดอะไรขึ้นเมื่อพิมพ์เว็บไซต์ (คำถามคลาสสิก)
1. พิมพ์ URL ในเบราว์เซอร์
2. เบราว์เซอร์ถาม DNS หา IP address
3. DNS ตอบกลับ IP address
4. เบราว์เซอร์เชื่อมต่อไปยัง web server
5. Server ตอบกลับและเว็บไซต์แสดงผล

### TCP 3-Way Handshake
Client ส่ง **SYN** → Server ตอบ **SYN-ACK** → Client ส่ง **ACK** กลับ — ทำให้ทั้งสองฝ่ายพร้อมสื่อสารกันก่อนส่งข้อมูลจริง (ใช้กับ TCP เท่านั้น)

### TCP vs UDP
- **TCP**: connection-oriented, มี 3-way handshake, reliable (มี acknowledgement/error recovery), ใช้กับ HTTP/HTTPS, SSH, FTP, Email
- **UDP**: connectionless, ไม่มี acknowledgement, เร็วกว่าแต่ไม่รับประกันการส่งถึง, ใช้กับ DNS, VoIP, streaming, gaming

### Protocol/พอร์ตสำคัญที่ต้องรู้
| Port | Protocol | Service | ใช้ทำอะไร |
|------|----------|---------|-----------|
| 22 | TCP | SSH | remote access แบบเข้ารหัส |
| 53 | TCP/UDP | DNS | แปลงชื่อโดเมนเป็น IP |
| 80 | TCP | HTTP | web traffic (ไม่เข้ารหัส) |
| 443 | TCP | HTTPS | web traffic (เข้ารหัส) |
| 445 | TCP | SMB | file sharing, ใช้ lateral movement บ่อย |
| 3389 | TCP | RDP | remote desktop, เป้าหมายยอดฮิตของการโจมตี |
| 25 | TCP | SMTP | ส่งอีเมล |
| 110 | TCP | POP3 | รับอีเมล |
| 995 | TCP | IMAP(S) | รับอีเมลแบบเข้ารหัส |

### Private IP vs Public IP และ NAT
- **Private IP**: ใช้ภายใน LAN, ไม่ routable บนอินเทอร์เน็ต (เช่น 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- **Public IP**: ใช้บนอินเทอร์เน็ต, unique และ routable ทั่วโลก, จัดสรรโดย ISP/Cloud
- **NAT (Network Address Translation)**: แปลง private IP หลายเครื่องให้ออกอินเทอร์เน็ตผ่าน public IP เดียว — ช่วยประหยัด public IP, เพิ่มชั้นความปลอดภัย, ซ่อนโครงสร้างภายใน

### แนวคิดสำคัญอื่นๆ
Subnetting/CIDR, VLAN segmentation, routing table เบื้องต้น — attacker มักใช้ protocol เดียวกับที่ user ทั่วไปใช้ ดังนั้นการเข้าใจพื้นฐานเครือข่ายให้แม่นจะช่วยให้สืบสวนได้เร็วขึ้น

---

## 5. Network Security

### อุปกรณ์/แนวคิดหลัก
- **Firewall** – ตรวจสอบ traffic ตาม rule (source IP, destination IP, port, protocol, action, direction) แล้วตัดสินใจ Allow/Deny (คุณมีประสบการณ์ Fortinet/SonicWall อยู่แล้ว ใช้พูดได้เลย)
- **IDS vs IPS**
  - IDS (Intrusion Detection System): ตรวจจับ + แจ้งเตือนเท่านั้น เป็น passive monitoring (ตัวอย่าง: Snort ในโหมด IDS)
  - IPS (Intrusion Prevention System): ตรวจจับ + บล็อกทันที ทำงานแบบ inline (ตัวอย่าง: Suricata IPS, Palo Alto IPS)
- **VPN** – เข้ารหัสการเชื่อมต่อระยะไกล
- **Network Segmentation** – แบ่ง zone (DMZ, internal, guest) เพื่อจำกัด lateral movement
- **Zero Trust** – "never trust, always verify" ไม่เชื่อ traffic แม้จะอยู่ใน internal network

### การโจมตีเครือข่ายที่พบบ่อย
- **Port Scanning** – สแกนหาพอร์ตเปิดก่อนโจมตี (มักเป็นสัญญาณ recon)
- **DDoS** – ทำให้ระบบล่มด้วย traffic จำนวนมาก
- **DNS Tunneling** – ขโมยข้อมูลผ่าน DNS query
- **ARP Spoofing** – ผู้โจมตีส่งข้อมูล ARP ปลอมไปหาทั้งเหยื่อและเป้าหมาย ทำให้ traffic ถูกส่งผ่านเครื่องผู้โจมตีก่อน เปิดทางให้เกิด **Man-in-the-Middle (MITM)**
- **Data Exfiltration** – ส่งข้อมูลออกไปยังปลายทางภายนอกโดยไม่ได้รับอนุญาต
- **C2 Communication** – มัลแวร์เชื่อมต่อกลับไปหา Command & Control server

### วิธีสืบสวน unusual outbound traffic (คำถามยอดฮิต)
1. **Identify Source** – เช็ค host/user/process ต้นทาง
2. **Check Destination** – ตรวจสอบ IP/domain/port/protocol ปลายทาง
3. **Analyze Logs** – ดู firewall, proxy, DNS, EDR logs ประกอบกัน
4. **Check Reputation** – ใช้ threat intel เช็ค reputation ของ IP/domain
5. **Analyze Pattern** – ดู volume, frequency, เวลาที่เกิด
6. **Document & Escalate** – บันทึกและส่งต่อถ้าพบว่าเป็นภัยจริง

### Log ที่สำคัญในการสืบสวนเครือข่าย
Firewall Logs (allow/deny, traffic pattern), Proxy Logs (web activity, URL, user behavior), DNS Logs (query, domain แปลก, DNS tunneling), VPN Logs (login, location, session), IDS/IPS Logs (alert, signature, attack attempt)

**หลักคิดสำคัญ**: Context + Evidence = การตัดสินใจที่ถูกต้อง — ไม่ใช่ traffic แปลกทุกตัวจะเป็นภัย แต่ภัยทุกตัวมักดู "แปลก" เสมอ

---

## 6. SIEM & Log Analysis (+ Splunk)

### SIEM คืออะไร
Security Information and Event Management – รวบรวม log จากหลายแหล่ง (firewall, server, endpoint, application, cloud) มา correlate และสร้าง alert แบบรวมศูนย์ เพื่อให้เห็น visibility แบบ real-time, ตรวจจับภัยได้เร็วขึ้น, และรองรับ compliance reporting (PCI-DSS, ISO 27001, GDPR)

### ตัวอย่าง SIEM ที่นิยม
Splunk, IBM QRadar, Microsoft Sentinel, Elastic (ELK), และ **Wazuh** (ที่คุณกำลังทำ lab อยู่ — เป็น open-source SIEM/XDR ที่ใช้ได้ทั้ง log analysis และ endpoint monitoring)

### หลักการทำงานของ SIEM: Collect → Normalize → Correlate → Detect → Respond
1. **Collect** – รวบรวม log จากหลายแหล่ง
2. **Normalize** – แปลง log ให้อยู่ในรูปแบบมาตรฐานเดียวกัน
3. **Correlate** – หา pattern และเชื่อมโยงเหตุการณ์ที่เกี่ยวข้อง
4. **Detect** – ตรวจจับภัยและกิจกรรมน่าสงสัย
5. **Respond** – สร้าง alert/ticket และเริ่มกระบวนการตอบสนอง

### Log Source สำคัญที่ SOC ต้องดู
- Windows/Linux server logs
- Firewall & network device logs
- Authentication logs (AD, VPN)
- Web servers & applications
- Email gateways
- EDR & security tools
- Cloud platforms (AWS, Azure, GCP)

### ประเภทของ Log ใน SOC
Authentication Logs (logon/logoff, failed login, privilege change), System Logs (process creation, service change), Network Logs (traffic allow/deny, DNS query, VPN connection), Application Logs (error, user activity, file access), Security Logs (malware detection, IDS/IPS alert, policy violation)

### Windows Event ID ที่ SOC ต้องรู้จัก
4624 = logon สำเร็จ, 4625 = logon ล้มเหลว, 4688 = process creation, 4768/4769 = Kerberos ticket request

### ตัวอย่าง Correlation Scenario
```
10:10 AM  Failed Login   User: admin  IP: 10.0.0.5
10:11 AM  Failed Login   User: admin  IP: 10.0.0.5
10:12 AM  Successful Login  User: admin  IP: 10.0.0.5
→ ALERT: หลาย failed login ตามด้วยการ login สำเร็จจาก IP เดียวกัน = สงสัย brute-force attack
```
ตรงกับ test case ที่คุณกำลังทำใน Wazuh lab (failed SSH login) พอดี

### Log Retention
ควรเก็บ log อย่างน้อย 90 วัน–1 ปี ตามนโยบายองค์กร/กฎหมาย (ที่ไทยมีประเด็น PDPA และ พ.ร.บ.คอมพิวเตอร์ที่กำหนดการเก็บ log ผู้ให้บริการ)

### Splunk Architecture (มักถูกถามถ้าองค์กรใช้ Splunk)
Data Sources → **Forwarders** (เก็บและส่ง log ไปยัง indexer) → **Indexers** (จัดทำ index และเก็บ log ให้ค้นหาได้) → **Search Head** (จัดการ search request และแสดงผล) → Dashboards/Alerts/Reports

### ตัวอย่าง Splunk Search (SPL)
```
index=firewall sourcetype=firewall_logs action=blocked
| stats count by src_ip
| where count > 50
| sort - count
```
คำสั่งนี้หา IP ที่ถูก firewall บล็อกมากกว่า 50 ครั้ง เรียงจากมากไปน้อย — ใช้ตรวจจับ brute-force หรือ scanning attempt ได้

### Splunk Search Modes
- **Fast Mode**: ใช้เฉพาะ indexed data, เร็วแต่ผลลัพธ์จำกัด (default)
- **Smart Mode**: ใช้ทั้ง indexed และ raw data, สมดุลระหว่างความเร็วและความละเอียด
- **Verbose Mode**: ใช้ raw data เต็มรูปแบบ, ช้าแต่ครบถ้วนที่สุด

### เทคนิคเขียน search ให้เร็วขึ้น
ระบุ time range ให้ชัด, ใช้ index/sourcetype ระบุแหล่งข้อมูล, filter ด้วย search command ตั้งแต่ต้น, หลีกเลี่ยง wildcard นำหน้า (เช่น `*error`), ใช้ fields แทน regex เมื่อทำได้, สรุปข้อมูลด้วย stats ก่อนทำ operation หนักๆ

*(หมายเหตุ: ถ้าอยากได้ diagram ประกอบหัวข้อ SIEM/Splunk เช่น Splunk architecture หรือ log correlation flow บอกได้ ผมวาดใหม่ให้เป็น SVG ได้)*

---

## 7. EDR & Endpoint Security

### EDR คืออะไร
Endpoint Detection and Response – ซอฟต์แวร์ที่ติดตั้งบนเครื่อง endpoint (laptop, server, workstation) เพื่อเฝ้าดูพฤติกรรม process, file, registry แบบ real-time และตอบสนองได้อย่างรวดเร็ว

### ความแตกต่าง: Antivirus vs EDR vs XDR
- **Antivirus (AV)**: signature-based, จับมัลแวร์ที่รู้จักแล้ว
- **EDR**: behavior-based, จับ pattern ผิดปกติ, มี response capability (isolate, kill process)
- **XDR (Extended Detection and Response)**: ขยายจาก EDR ให้ครอบคลุมหลาย layer (network, email, cloud) ในแพลตฟอร์มเดียว

### EDR Key Capabilities
Real-time threat detection, behavioral analysis, process monitoring, file/script analysis, network connection monitoring, IOC detection, automated response actions, forensic data collection

### สิ่งที่ควรเช็คเวลาตรวจสอบ alert ใน EDR
- **Process Tree** (parent-child relationship) – ผู้โจมตีมักใช้ process ที่ถูกกฎหมาย (เช่น Word) มารัน process อันตราย (เช่น powershell.exe → cmd.exe) ถ้าเกิดขึ้นแบบไม่คาดคิดถือว่าน่าสงสัย
- **File Hash** – ตรวจสอบ path, hash, signer, reputation ของไฟล์
- **User Context** – ใครเป็นคนรัน process/action นี้
- **Network Connections** – เชื่อมต่อไปที่ IP/domain ไหนบ้าง
- **Timeline** – ลำดับเหตุการณ์ทั้งหมด

### สัญญาณที่ EDR มักจับได้
- LOLBins (Living-off-the-Land Binaries เช่น powershell.exe, certutil.exe ถูกใช้ในทางที่ผิด)
- Suspicious script/malicious process
- C2 communication
- Credential theft (เช่น Mimikatz เข้าถึง LSASS)
- USB activity ที่น่าสงสัย
- Privilege escalation attempt

### EDR Response Actions
Isolate Endpoint (ตัดเครื่องออกจากเครือข่าย), Kill Process, Quarantine File, Block IOCs (IP/domain/hash/URL), Collect Forensic Data (memory dump, log), Generate Report

### EDR Investigation Workflow
Alert Triggered → Triage → Analyze (process tree, file, network, user) → Investigate (เก็บหลักฐาน, validate) → Respond (isolate/kill/block) → Report

### เชื่อมกับประสบการณ์
คุณใช้ NinjaOne สำหรับ patch management อยู่แล้ว — อธิบายได้ว่า patching เป็นส่วนหนึ่งของ endpoint hygiene ที่ช่วยลด attack surface ก่อนที่ EDR จะต้องเข้ามาจับ

---

## 8. Web Proxy Fundamentals

### Web Proxy คืออะไร
Web Proxy ทำหน้าที่เป็นตัวกลางระหว่าง user กับอินเทอร์เน็ต โดยขอหน้าเว็บแทนผู้ใช้ ตรวจสอบเนื้อหา แล้วส่งเฉพาะเนื้อหาที่ปลอดภัยกลับไป

### Key Functions ของ Web Proxy
Traffic Filtering, Access Control, Content Caching, Threat Protection, Logging & Monitoring, Bandwidth Optimization

### รูปแบบการ deploy Proxy
- **Forward Proxy** – client ใช้เชื่อมต่อออกอินเทอร์เน็ต ช่วยซ่อน client IP (เช่น Blue Coat, Zscaler Forward Proxy)
- **Reverse Proxy** – อยู่หน้า web server เพื่อป้องกันไม่ให้ server ถูกเข้าถึงตรงจากอินเทอร์เน็ต (เช่น Nginx, HAProxy)
- **Transparent Proxy** – ดัก traffic โดยไม่ต้อง config ที่ฝั่ง user ทำงานระดับ network

### Web Proxy อนุญาต/บล็อกอะไรบ้าง
- **Allow**: เว็บไซต์ธุรกิจ, software update, เว็บการศึกษา, SaaS application
- **Block**: เว็บอันตราย, social media (ถ้ามีนโยบายจำกัด), streaming, file sharing site

### Log ที่ Proxy เก็บและใช้สืบสวนได้
Web activity, URL ที่เข้าถึง, download history, user behavior — เป็น log source สำคัญเวลาสืบสวน phishing link click หรือ data exfiltration ผ่านเว็บ

### Common Proxy Features
URL Filtering, SSL Inspection, Content Caching, DLP (Data Loss Prevention), User Authentication, Application Control, Geo-IP Blocking, Malware Scanning

---

## 9. Email & Phishing Security

### ประเภทของ Phishing
- **Phishing** ทั่วไป – ส่งอีเมลหลอกจำนวนมาก
- **Spear Phishing** – เจาะจงเป้าหมายรายบุคคล
- **Whaling** – เจาะจงผู้บริหารระดับสูง
- **Business Email Compromise (BEC)** – ปลอมเป็นผู้บริหาร/คู่ค้าเพื่อหลอกโอนเงิน
- **Malware** – ไฟล์/ลิงก์อันตรายที่ทำให้ระบบติดมัลแวร์
- **Spam** – อีเมลไม่พึงประสงค์จำนวนมาก มักมีเจตนาไม่ดี

### Email Security Gateway Workflow
Sender → Internet → **Email Security Gateway** (ทำ Sender Authentication, Spam Filtering, URL/Attachment Scanning, Content Analysis, Policy Enforcement, Threat Detection) → Mail Server → Recipient

### วิธีตรวจสอบอีเมลต้องสงสัย (สิ่งที่ SOC Analyst ต้องทำได้)
1. ตรวจ **header** – Return-Path, Received chain, IP ต้นทาง
2. ตรวจ **SPF, DKIM, DMARC** – ป้องกันการปลอมแปลง sender
3. ตรวจลิงก์/attachment ด้วย sandbox หรือ VirusTotal
4. เช็ค urgency/social engineering pattern ในเนื้อหา

### Email Authentication Explained
- **SPF (Sender Policy Framework)**: ยืนยันว่าอีเมลถูกส่งจาก mail server ที่ได้รับอนุญาตของโดเมนนั้นจริง
- **DKIM (DomainKeys Identified Mail)**: เพิ่มลายเซ็นดิจิทัลเพื่อยืนยันว่าเนื้อหาอีเมลไม่ถูกแก้ไข
- **DMARC (Domain-based Message Authentication, Reporting & Conformance)**: กำหนดว่าผู้รับควรทำอย่างไรเมื่อ SPF/DKIM ล้มเหลว (quarantine/reject) พร้อมส่ง report กลับ

### Phishing Email Indicator Checklist
| ตัวชี้วัด | สิ่งที่ต้องเช็ค |
|-----------|----------------|
| Sender Address | ที่อยู่ผู้ส่งดูน่าสงสัยหรือสะกดต่างจากของจริงเล็กน้อยหรือไม่ |
| Unusual Links | เอาเมาส์ชี้ลิงก์แล้วดูว่าตรงกับโดเมนจริงหรือไม่ |
| Urgency/Threats | เนื้อหาสร้างความเร่งด่วนหรือขู่หรือไม่ |
| Grammar/Spelling | มีคำผิดหรือไวยากรณ์แปลกหรือไม่ |
| Unexpected Attachments | ได้รับไฟล์แนบที่ไม่คาดคิดหรือไม่ |
| Request for Info | ขอรหัสผ่าน/OTP/ข้อมูลอ่อนไหวหรือไม่ |

### Incident Response สำหรับ Email Threats
Identify (ตรวจจับอีเมลน่าสงสัย) → Analyze (เช็ค header/links/attachment) → Contain (block sender, quarantine) → Eradicate (ลบมัลแวร์, block IOC) → Recover (คืนสิทธิ์การเข้าถึง, monitor) → Lessons Learned (ปรับ policy, ให้ความรู้ user)

### Indicators of Compromise (IOC) จาก phishing
IP/domain ปลายทาง, file hash ของ attachment, URL ที่ปลอมแปลง

---

## 10. Active Directory Security

### แนวคิดพื้นฐาน
AD เป็นศูนย์กลาง identity/authentication ขององค์กร จัดการ users, computers, groups, permissions และ security policy — เป็นเป้าหมายอันดับต้นๆ ที่ผู้โจมตีต้องการยึดครอง (ถ้ายึด AD ได้เท่ากับยึดทั้งองค์กร)

### AD Key Components
Domain, Organizational Units (OUs), Users & Groups, Computers, Policies (GPOs), Trusts & Relationships

### การโจมตี AD ที่พบบ่อย (มักถูกถามในสัมภาษณ์)
- **Credential Theft** – brute force, phishing, pass-the-hash
- **Pass-the-Hash / Pass-the-Ticket** – ใช้ hash หรือ Kerberos ticket ที่ขโมยมาโดยไม่ต้องรู้รหัสผ่านจริง
- **Kerberoasting** – ขอ service ticket แล้วนำไป crack แบบ offline เพื่อได้รหัสผ่าน service account
- **Golden Ticket / Silver Ticket** – ปลอมแปลง Kerberos ticket เพื่อเข้าถึงระบบโดยไม่ต้องรู้รหัสผ่านจริง
- **Unconstrained Delegation** – ช่องโหว่ config ที่เปิดให้ผู้โจมตีปลอมเป็นผู้ใช้ใดก็ได้
- **Privilege Escalation** – ใช้ misconfiguration เพื่อยกระดับสิทธิ์เป็น admin
- **Excessive Permissions** – บัญชีที่มีสิทธิ์เกินความจำเป็นเพิ่มความเสี่ยง

### Key AD Security Objects
Domain Controller (DC) – ยืนยันตัวตนและบังคับใช้ policy; Group Policy Objects (GPO) – ควบคุม config ทั่วทั้ง domain; Organizational Units (OU) – จัดกลุ่ม users/computers; Security Groups – กำหนดสิทธิ์การเข้าถึง; Trusts – ความสัมพันธ์ระหว่าง domain

### Important AD Event IDs ที่ต้อง monitor
| Event ID | ความหมาย | ทำไมสำคัญ |
|----------|----------|-----------|
| 4624 | Logon สำเร็จ | ติดตามการ logon ปกติ |
| 4625 | Logon ล้มเหลว | ตรวจจับ brute force |
| 4672 | ให้สิทธิ์พิเศษ | admin หรือ high privilege logon |
| 4720 | สร้าง user account | เฝ้าระวังการสร้าง account ที่ไม่ได้รับอนุญาต |
| 4728 | เพิ่มสมาชิกเข้า global group | ตรวจจับ privilege escalation |
| 4740 | บัญชีถูก lock | ตรวจจับ brute force/lockout attack |
| 5136 | มีการเปลี่ยนแปลงใน Directory | เฝ้าระวังการแก้ไข AD object |

### Essential AD Security Best Practices
บังคับ strong password policy + MFA สำหรับ admin, ใช้หลัก least privilege, audit บัญชีสิทธิ์สูงเป็นประจำ, เปิด account lockout policy, patch Domain Controller สม่ำเสมอ, ใช้ LAPS สำหรับ local admin password, monitor AD log และตั้ง alert, backup AD สม่ำเสมอและทดสอบการกู้คืน

### AD Security Monitoring Tools
Microsoft Defender for Identity, Splunk, PingCastle, BloodHound, Azure AD Identity Protection

---

## 11. Vulnerability Management

### วงจร Vulnerability Management (5 ขั้นตอน)
1. **Discover/Identify** – ค้นหา asset และช่องโหว่
2. **Assess** – ประเมินความเสี่ยงและผลกระทบทางธุรกิจ
3. **Prioritize** – จัดลำดับตามความเสี่ยงและความรุนแรง
4. **Remediate** – แก้ไขหรือลดความเสี่ยง
5. **Monitor** – ยืนยันและเฝ้าติดตามต่อเนื่อง

### Vulnerability Identification Process
Define Scope (ระบุ asset/ระบบ) → Select Tools (เลือก scanner ที่เหมาะสม) → Scan (รันสแกนและเก็บข้อมูล) → Analyze (validate และตัด false positive ออก) → Report (สร้างรายงานและแชร์ผล)

### ประเภทของ Vulnerability Scan
| ประเภท | คำอธิบาย |
|--------|----------|
| Network Scan | สแกน IP range, host, port และ service |
| Host-Based Scan | สแกน OS และแอปพลิเคชันที่ติดตั้ง |
| Web Application Scan | หาช่องโหว่เว็บแอป เช่น SQLi, XSS, CSRF |
| Wireless Scan | ตรวจจับจุดอ่อนของ Wi-Fi |
| Cloud Infrastructure Scan | สแกน cloud asset และ misconfiguration |

### เครื่องมือ Vulnerability Scanning ที่นิยม
Qualys (cloud-based platform), Nessus (widely used scanner โดย Tenable), OpenVAS (open source), Rapid7 InsightVM (risk-based), Acunetix (เน้น web application)

### Authenticated vs Unauthenticated Scan
- **Unauthenticated**: ไม่ใช้ credential, มองเห็นได้จำกัด, เร็วกว่า, เหมาะกับ external scan
- **Authenticated**: ใช้ credential จริง, เห็นข้อมูลลึกและแม่นยำกว่า, ช้ากว่า, เหมาะกับ internal scan (ต้องจัดการสิทธิ์ให้ปลอดภัย)

### CVSS (Common Vulnerability Scoring System)
มาตรฐานให้คะแนนความรุนแรงของช่องโหว่ (0.0–10.0) จาก Base, Temporal, และ Environmental Metrics

| Score Range | Severity | Action |
|-------------|----------|--------|
| 9.0–10.0 | Critical | แก้ไขทันที |
| 7.0–8.9 | High | วางแผนและแก้ไข ASAP |
| 4.0–6.9 | Medium | จัดตารางแก้ไข |
| 0.1–3.9 | Low | เฝ้าระวังและแก้ไข |
| 0.0 | Informational/None | ไม่ต้องดำเนินการ |

### Risk = Threat x Vulnerability x Impact
ความเสี่ยงไม่ได้ขึ้นกับ CVSS อย่างเดียว แต่ต้องพิจารณา **Asset Criticality** ด้วย — ช่องโหว่ระดับ Medium บน asset สำคัญมาก อาจมีความเสี่ยงสูงกว่าช่องโหว่ระดับ High บน asset ที่ไม่สำคัญ

### ปัจจัยด้าน Exploitability ที่ใช้จัดลำดับความสำคัญ
มี public exploit หรือไม่, มี exploit code พร้อมใช้ (เช่น Metasploit) หรือไม่, กำลังถูกใช้โจมตีจริงในโลกจริงหรือไม่ (active exploitation), asset เปิดสู่อินเทอร์เน็ตหรือไม่ (internet-facing), และง่ายต่อการโจมตีแค่ไหน

### Remediation & Patch Management Process
Identify (หา patch ที่ขาด) → Assess (ประเมินความเสี่ยง/ผลกระทบทางธุรกิจ) → Acquire (ดาวน์โหลด patch) → Deploy (ทดสอบและ deploy เป็นเฟส) → Verify (ยืนยันว่า patch สำเร็จ) → Document (บันทึกและปิดงาน)

### Patch Types
Security Patch (ปิดช่องโหว่), Critical Patch (แก้ zero-day/high-risk flaw), Feature Patch (เพิ่มฟีเจอร์), Bug/Hotfix (แก้บั๊กหรือความเสถียร)

### Patch Deployment Best Practices
ทดสอบใน staging ก่อนเสมอ, สำรองข้อมูลก่อน deploy, ทำตาม change management process, deploy เป็นเฟส (Pilot → Group → Organization), monitor ระบบหลัง patch, เตรียมแผน rollback ไว้เสมอ, ยืนยันผลด้วยเครื่องมือสแกนซ้ำ

### Remediation Prioritization (P1–P5)
| Priority | CVSS Score | Action |
|----------|-----------|--------|
| P1 – Critical | 9.0–10.0 | แก้ไขทันที |
| P2 – High | 7.0–8.9 | วางแผน+แก้ไขโดยเร็ว |
| P3 – Medium | 4.0–6.9 | จัดตารางแก้ไข |
| P4 – Low | 0.1–3.9 | เฝ้าระวังและแก้ไข |
| P5 – Informational | 0.0 | ไม่ต้องดำเนินการ/เฝ้าดู |

**หลักสำคัญ**: จัดลำดับความสำคัญตาม CVSS + Asset Criticality + Exploitability ร่วมกัน ไม่ใช่ดู CVSS อย่างเดียว

### Common Challenges ใน Vulnerability Management
False Positives (เสียเวลากับผลลัพธ์ที่ไม่เกี่ยวข้อง), Scan Window ที่จำกัดในสภาพแวดล้อมใหญ่, ปัญหาสิทธิ์เข้าถึงสำหรับ authenticated scan, Data Overload (ผลสแกนเยอะจนจัดลำดับยาก), Downtime ระหว่าง patch, Legacy Systems ที่ patch ยาก

### แหล่งข้อมูล Vulnerability ที่ควรรู้จัก
NVD (National Vulnerability Database), CISA KEV (Known Exploited Vulnerabilities), MITRE CVE, OSV (Open Source Vulnerability database), Vendor Advisories

### CVE vs CVSS (จุดที่มักสับสน)
- **CVE**: หมายเลขเฉพาะที่ใช้ระบุช่องโหว่แต่ละตัว
- **CVSS**: ระบบให้คะแนนความรุนแรงของช่องโหว่นั้น

### Vulnerability Scanning vs Penetration Testing
| | Vulnerability Scanning | Penetration Testing |
|---|---|---|
| Purpose | หาช่องโหว่ที่รู้จัก | โจมตีจริงเพื่อดูผลกระทบ |
| Approach | เครื่องมืออัตโนมัติ | Manual + Automated |
| Depth | กว้างแต่ตื้น | ลึกและเจาะจง |
| Frequency | ทำสม่ำเสมอ (รายสัปดาห์/เดือน) | เป็นช่วง (รายไตรมาส/ปี) |
| Output | รายชื่อช่องโหว่ | รายงาน exploit และผลกระทบจริง |

### เชื่อมกับประสบการณ์
เชื่อมกับ NinjaOne ที่คุณใช้ patch management อยู่แล้ว — พูดได้ว่าคุณเข้าใจ workflow ตั้งแต่ scan ถึง patch จริง ไม่ใช่แค่ทฤษฎี

---

## 12. Threat Intelligence

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

## 13. MITRE ATT&CK

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

*(หมายเหตุ: matrix จริงจาก mitre.org ดูได้ที่ attack.mitre.org — ถ้าอยากได้ diagram สรุป 11 tactics แบบย่อ บอกได้ ผมวาดให้ใหม่ได้)*

---

## 14. Security Monitoring & Detection

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

## 15. Practical Investigation Scenarios

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

## 16. Common SOC Interview Questions

### คำถามความรู้ทั่วไป
- SOC Tier 1, 2, 3 ต่างกันอย่างไร?
- อธิบายความแตกต่างระหว่าง IDS กับ IPS
- SIEM ทำงานอย่างไร และทำไมองค์กรถึงต้องมี?
- อธิบาย incident response lifecycle (NIST)
- MITRE ATT&CK คืออะไร และใช้งานอย่างไร?
- SPF, DKIM, DMARC ต่างกันอย่างไร?
- อธิบายความแตกต่างระหว่าง vulnerability กับ threat กับ risk
- Web Proxy ทำงานอย่างไร และต่างจาก Firewall อย่างไร?

### คำถามเฉพาะทาง Vulnerability Management
- Vulnerability Management คืออะไร?
- ขั้นตอนหลักของ Vulnerability Management lifecycle มีอะไรบ้าง?
- Vulnerability กับ Risk ต่างกันอย่างไร? (Risk = Threat x Vulnerability x Impact)
- CVSS คืออะไร?
- Authenticated กับ Unauthenticated scan ต่างกันอย่างไร?
- Patch คืออะไร และสำคัญอย่างไร?
- ฐานข้อมูลช่องโหว่ที่รู้จักมีอะไรบ้าง? (NVD, CISA KEV, MITRE CVE)
- Firewall/IPS ช่วยงาน Vulnerability Management อย่างไร?
- ความท้าทายของ Vulnerability Management คืออะไรบ้าง?
- รายงานช่องโหว่ควรมีอะไรบ้าง?
- CVE กับ CVSS ต่างกันอย่างไร?
- Penetration testing มีจุดประสงค์อะไรใน Vulnerability Management?
- ใครคือ stakeholder หลักที่เกี่ยวข้องกับ Vulnerability Management?
- คุณจัดลำดับความสำคัญของช่องโหว่อย่างไร?

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
2. ลองตอบ Scenario ในหัวข้อ 15 แบบพูดออกเสียง (mock interview) จับเวลา 2-3 นาทีต่อคำถาม
3. ทบทวน MITRE ATT&CK Matrix คร่าวๆ 1 รอบ (ไม่ต้องจำทุก technique แค่เข้าใจ 11 tactics และยกตัวอย่างได้)
4. ลองเขียน Splunk SPL query ง่ายๆ เอง 2-3 ตัว (เช่น หา top blocked IP, หา failed login เกิน threshold)

---
*จัดทำโดย Claude สำหรับการเตรียมสัมภาษณ์ SOC Analyst — อัปเดตล่าสุด 27 ส.ค. 2026*

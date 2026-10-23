# สถาปัตยกรรมระบบสแกนความปลอดภัย

เอกสารนี้อธิบายเว็บต้นแบบใน [index.html](./index.html), การตรวจ Wi-Fi ในเครื่องด้วย PowerShell, การสแกนไฟล์ในเครื่องด้วย Microsoft Defender และ backend สำหรับสแกนไฟล์ด้วย ClamAV/YARA ผ่าน FastAPI, Celery, Redis และ PostgreSQL.

## สถานะการใช้งานปัจจุบัน

GitHub Pages ให้บริการหน้าเว็บแบบ static เท่านั้น และไม่มี Backend ที่เชื่อมต่ออยู่ในค่าเริ่มต้น หน้า Dashboard กำหนดให้เข้าสู่ระบบด้วย Firebase Authentication; หลังเข้าสู่ระบบจึงใช้การวิเคราะห์ซอร์สโค้ดใน browser, ตรวจ npm dependency ผ่าน OSV, วิเคราะห์รายงาน Wi-Fi และแสดงรายงาน Microsoft Defender ได้ ส่วนการสแกน ClamAV/YARA และการตรวจเว็บไซต์ผ่าน Backend ต้องมี API/worker ที่เปิดใช้งานและกำหนด `scanner-api-base` ก่อน บัญชี Firebase ไม่ได้เปิด Backend ให้เอง

หน้าเว็บไม่มีการเปิด Firebase Analytics; โค้ดที่เลือกตรวจและรายงาน Wi-Fi/Defender ประมวลผลใน browser โดยไม่อัปโหลดอัตโนมัติ ชื่อ/เวอร์ชัน dependency จะส่งไปยัง OSV เมื่อผู้ใช้กดยินยอม และไฟล์ไวรัสจะอัปโหลดเมื่อผู้ใช้สั่งสแกนผ่าน Backend ที่ตั้งค่าไว้

## 1. เป้าหมายและขอบเขต

ระบบต้นแบบปัจจุบันตรวจสอบรายการต่อไปนี้ เฉพาะเป้าหมาย/ไฟล์ที่ผู้ใช้มีสิทธิ์ตรวจ:

- **HTTP security headers:** Backend ตรวจ URL แล้วส่งคำขอ `HEAD` หนึ่งครั้ง โดยมี timeout และตรวจ DNS/IP; endpoint นี้ยังทำงานใน request ไม่ได้เข้าคิว Celery
- **TLS certificate:** ยังไม่มี backend checker; หน้าเว็บระบุความสามารถนี้ว่า “ต้องมี Backend”
- **Dependency:** หน้าเว็บอ่านไฟล์ npm ที่ผู้ใช้เลือกและถาม OSV API เมื่อผู้ใช้เริ่มตรวจ ไม่ได้ดึง CVE feed รายวันหรืออัปเดต scanner plugins
- **Source code:** ตรวจแบบ static ใน browser โดยไม่ execute โค้ด; ยังไม่มี source-code scanner task ใน Celery worker
- **Virus scan:** เลือกสแกนไฟล์ในเครื่องด้วย Microsoft Defender โดยไม่อัปโหลดไฟล์ หรือเลือกอัปโหลดไฟล์เข้า quarantine เพื่อสแกนด้วย ClamAV; โหมด backend แบบลึกเพิ่ม YARA heuristic rules
- **Wi-Fi:** Windows helper อ่านสถานะเครือข่ายที่เชื่อมต่ออยู่; การวิเคราะห์ทำใน browser หรือส่งรายงานโดยสมัครใจไปยัง endpoint ที่ตรวจ Firebase ID token และไม่บันทึกรายงาน
- **รายงาน:** ผลในหน้าเว็บและประวัติอยู่ในหน่วยความจำ browser; Backend เก็บ metadata/ผลสแกนไฟล์ใน PostgreSQL แต่ยังไม่มี API สำหรับประวัติรายการสแกน
- **สรุปผลภาษาไทย:** Backend สร้างข้อความจาก rule-based template เท่านั้น ยังไม่ได้เชื่อม AI model; CVE feed เป็น optional request-based integration ไม่ได้ดึงรายวันและไม่อัปเดต scanner rules อัตโนมัติ

การสแกนในเครื่องเรียก Microsoft Defender บน Windows และบันทึกเฉพาะรายงานไว้ในเครื่อง ไม่ส่งไฟล์หรือ path ไปยังเว็บ Defender อาจกักกันหรือลบภัยคุกคามตามการตั้งค่าของ Windows โหมด backend ไม่รันไฟล์ที่อัปโหลด และลบไฟล์จาก quarantine หลัง worker จบงาน (กรณี worker หยุดผิดปกติ ระบบลบไฟล์ค้างที่เก่ากว่า 24 ชั่วโมงตอนเริ่ม API)

**ยังไม่มี implementation ในโปรเจกต์:** ZAP, Nuclei, Nmap และ WPScan รวมถึงการสแกน TLS certificate แบบ backend การสแกนทั้งเครื่องผู้ใช้, SQL injection/XSS exploitation, fuzzing, credential testing, brute force และการแก้ไขข้อมูลเป้าหมายไม่อยู่ในขอบเขตปัจจุบัน การสแกนเครือข่าย/เว็บไซต์แบบ active ต้องมี worker แยกและ allowlist ของเป้าหมายที่ได้รับอนุญาตก่อนพัฒนา

## 2. ภาพรวมสถาปัตยกรรม

```text
┌──────────────────────┐       HTTPS / JSON       ┌──────────────────────────┐
│ Frontend             │ ◄──────────────────────► │ FastAPI                  │
│ Dashboard / Reports  │                          │ API, Validation          │
└──────────────────────┘                          └────────────┬─────────────┘
                                                              │ enqueue
                                           ┌──────────────────┴──────────────┐
                                           ▼                                 ▼
                                  ┌─────────────────┐              ┌─────────────────┐
                                  │ Redis           │              │ PostgreSQL      │
                                  │ Celery broker   │              │ Jobs / findings │
                                  └────────┬────────┘              └─────────────────┘
                                           │ consume
                                           ▼
                                  ┌───────────────────────────────┐
                                  │ Celery scanning worker        │
                                  │ ClamAV | YARA file scans       │
                                  └──────────────┬────────────────┘
                                                 │
                           ┌─────────────────────┴───────────────────┐
                           ▼                                         ▼
                    Uploaded file (quarantine)             OSV vulnerability API
```

### ส่วนประกอบ

| ส่วน | หน้าที่ |
|---|---|
| Frontend | ทำ source/dependency checks ใน browser, ส่งไฟล์สแกน และแสดงสถานะ/ผล |
| FastAPI | รับไฟล์ขนาดจำกัดและ consent, สร้างงานสแกนไฟล์, ตรวจ health; website-header check เป็นคำขอ `HEAD` แบบ synchronous |
| Celery + Redis | จัดคิวงานสแกนไฟล์; PostgreSQL outbox ใช้กู้คืนการ dispatch และ Redis ใช้ AOF persistence |
| Celery workers | ตรวจไฟล์ด้วย ClamAV/YARA; ยังไม่มี task สำหรับ ZAP/Nuclei/Nmap/WPScan, TLS, dependency หรือ source code |
| PostgreSQL | เก็บ metadata, สถานะ และผลการสแกนไฟล์ |
| OSV API | หน้าเว็บ query รายการ dependency เมื่อผู้ใช้กดตรวจ; ไม่มี daily feed job ใน Backend |
| ClamAV + YARA | ตรวจ signature และ heuristic indicators ของไฟล์ที่อัปโหลด; ไม่ execute ไฟล์ |
| Microsoft Defender helper | ให้ Windows สแกนไฟล์ที่ผู้ใช้เลือกในเครื่อง และนำเข้ารายงาน JSON ใน browser; ไม่อัปโหลดไฟล์ |

## 3. ลำดับการทำงาน

1. ผู้ใช้เลือกไฟล์, โหมดตรวจ และยืนยันสิทธิ์อัปโหลด
2. Frontend ส่ง `POST /api/v1/virus-scans` เป็น `multipart/form-data`
3. FastAPI จำกัดขนาด 20 MiB, สร้างชื่อไฟล์จาก UUID, คำนวณ SHA-256 และเก็บไฟล์ไว้ใน quarantine volume
4. API สร้าง scan record และ outbox entry ใน transaction เดียว; Celery Beat ส่งงานจาก outbox ไป Redis และ retry งานที่ยัง queued; scan ใหม่ผูกกับ Firebase UID ของผู้สร้าง และทุก 10 นาที Beat จะเปลี่ยนงานที่ค้าง `running` เกิน 6 ชั่วโมงหรือ `queued` เกิน 24 ชั่วโมงเป็น `failed` (`scan_timeout`) พร้อมลบไฟล์ quarantine ที่ไม่มีงานค้างอยู่
5. Worker เปลี่ยนสถานะเป็น `running`; ClamAV ตรวจไฟล์ผ่าน clamd INSTREAM protocol และ deep mode เรียก YARA rules เพิ่ม
6. Worker บันทึกผลและคำแนะนำลง PostgreSQL แล้วลบไฟล์ชั่วคราว
7. Frontend อ่านสถานะ/ผลผ่าน `GET /api/v1/virus-scans/{scan_id}` พร้อม Firebase ID token (scan เก่าก่อน migration ใช้ `X-Scan-Token`)

สำหรับการสแกนในเครื่อง ผู้ใช้ดาวน์โหลด `virus-scan.ps1`, เรียกใช้บน Windows ที่เปิด Microsoft Defender Antivirus, เลือกไฟล์ผ่านหน้าต่าง native และนำเข้ารายงาน JSON ใน browser ไฟล์ที่เลือกและ path ไม่ถูกส่งไปยัง API; การอ่านรายงานเป็น local file operation

การอัปเดตสถานะรุ่นแรกใช้ polling ทุก 2–5 วินาที โดยมี backoff; เพิ่ม Server-Sent Events ได้ภายหลังหากจำเป็น

## 4. API และข้อมูลหลัก

### Endpoints รุ่นแรก

| Method | Endpoint | หน้าที่ |
|---|---|---|
| `POST` | `/api/v1/assets` | ลงทะเบียน asset และโดเมนที่อนุญาต |
| `GET` | `/api/v1/assets` | แสดง asset ของผู้ใช้ |
| `POST` | `/api/v1/scans` | สร้างงานสแกนตาม asset และชนิดที่อนุญาต |
| `GET` | `/api/v1/scans/{scan_id}` | อ่านสถานะ, เวลา และความคืบหน้า |
| `GET` | `/api/v1/scans/{scan_id}/findings` | อ่านผลแบบแบ่งหน้า |
| `GET` | `/api/v1/scans/{scan_id}/report` | ส่งออกรายงาน JSON |
| `GET` | `/api/v1/health` | ตรวจสถานะ API, PostgreSQL, Redis และ ClamAV |
| `GET` | `/wifi-scan.ps1` | ดาวน์โหลดตัวช่วยอ่านข้อมูล Wi-Fi ในเครื่อง Windows |
| `GET` | `/virus-scan.ps1` | ดาวน์โหลดตัวช่วยสแกนไฟล์ด้วย Microsoft Defender ในเครื่อง |
| `POST` | `/api/v1/virus-scans` | อัปโหลดไฟล์, เลือกโหมด `standard`/`deep` และสร้างงาน |
| `GET` | `/api/v1/virus-scans/{scan_id}` | อ่านสถานะและผลด้วย Firebase ID token ของเจ้าของ (scan เก่าใช้ `X-Scan-Token`) |
| `POST` | `/api/v1/wifi-reports` | รับและวิเคราะห์ JSON จากตัวช่วย Wi-Fi; ต้องใช้ Firebase ID token และไม่เก็บ SSID ในฐานข้อมูล |

Virus scan และ Wi-Fi report APIs ใช้งานได้; endpoints สำหรับ asset/website scans ในตารางเดิมเป็นแนวทางต่อยอดและยังไม่ได้ implement

การยกเลิกงาน (`DELETE /api/v1/scans/{scan_id}`) เพิ่มได้เมื่อ worker รองรับ cancellation อย่างปลอดภัย

### Entity ที่แนะนำ

- **User:** `id`, `email`, `password_hash` หรือ external identity, `created_at`
- **Asset:** `id`, `owner_id`, `canonical_domain`, `verification_status`, `created_at`
- **Scan:** `id`, `asset_id`, `requested_by`, `scan_type`, `status`, `created_at`, `started_at`, `completed_at`, `error_code`
- **Finding:** `id`, `scan_id`, `category`, `severity`, `title`, `description`, `evidence`, `remediation`, `source`, `external_id`, `cvss_score`, `created_at`

ค่าที่อนุญาตของ `status`: `queued`, `running`, `completed`, `failed`, `cancelled`

อย่าเก็บ credential, authorization header, cookie หรือเนื้อหาที่ไม่จำเป็นจากเว็บไซต์เป้าหมายลงใน finding หรือ log

## 5. มาตรการความปลอดภัยที่ต้องมี

### ป้องกัน SSRF และจำกัดเป้าหมาย

- ห้ามรับ URL อิสระจากผู้ใช้เพื่อส่งต่อให้ worker โดยตรง ให้สแกนเฉพาะ asset ใน allowlist ที่ผูกกับบัญชีผู้ใช้
- ยืนยันการควบคุมโดเมนก่อนเปิดใช้งาน asset เช่น DNS TXT challenge หรือไฟล์ HTTP challenge
- อนุญาตเฉพาะ `http`/`https` และพอร์ตที่กำหนดไว้; ปฏิเสธ URL ที่มี username/password, IP literal หรือรูปแบบ hostname ที่กำกวม
- resolve DNS ก่อนเชื่อมต่อและปฏิเสธ loopback, private, link-local, multicast, reserved และ metadata-service IP
- ป้องกัน DNS rebinding โดยตรวจ IP ที่เชื่อมต่อจริง; หากใช้ proxy หรือ connector ต้อง pin ปลายทางตามผลที่ตรวจแล้ว
- ปิด redirect โดยค่าเริ่มต้น หากจำเป็นต้องตาม redirect ให้ตรวจ allowlist และ resolve/validate IP ใหม่ทุก hop
- บังคับ egress firewall ของ worker ให้เข้าถึงได้เฉพาะเครือข่ายเป้าหมายที่อนุมัติและ API ฐานข้อมูลช่องโหว่ที่จำเป็น
- ส่ง `HEAD` เท่านั้นสำหรับ HTTP headers; จำกัด timeout, จำนวน redirect (ศูนย์เป็นค่าเริ่มต้น), response metadata และจำนวนงานต่อ asset

### Worker และ task queue

- แยก worker ตามชนิดงาน; static analysis และการอ่านไฟล์ควรทำใน container ที่ไม่ privileged และไม่มี network โดยไม่จำเป็น
- จำกัด CPU, memory, execution time, ขนาดไฟล์, จำนวนไฟล์, จำนวน dependency และ concurrency
- Redis ไม่ควรเปิดรับจาก public network; ใช้รหัสผ่าน/ACL, network isolation และ queue แยกตามประเภทงาน
- งานสแกนไฟล์ retry เมื่อ `ScannerUnavailableError` โดยจำกัด 2 ครั้งและใช้ backoff 5/10 วินาที; task ประเภทอื่นต้องกำหนด retry แยกตามลักษณะความผิดพลาด
- ออกแบบ task ให้ idempotent เพื่อป้องกันงานซ้ำเมื่อ worker หยุดกลางทาง
- เก็บ input ชั่วคราวนอก web root และลบตาม retention policy; ไม่ execute ไฟล์ที่ผู้ใช้อัปโหลด

### การจัดการไฟล์สแกน

- จำกัดไฟล์ไม่เกิน 20 MiB ต่อไฟล์ และอัปโหลดไม่เกิน 10 ไฟล์ต่อการส่งจาก UI
- ปฏิเสธ request สแกนที่ไม่มี `Content-Length` และจำกัดขนาด body ก่อนให้ multipart parser อ่านไฟล์
- ใช้ชื่อ UUID แทนชื่อที่ผู้ใช้อัปโหลดเป็น path; เก็บชื่อเดิมเป็น metadata ที่ escape ตอนแสดงผล
- สแกนไฟล์โดยอ่านเป็น stream ผ่าน ClamAV; ไม่แตก archive ด้วยโค้ดเว็บเอง
- ClamAV ใช้การประมวลผล archive ตามค่า engine; ควรตั้ง/ทบทวน `MaxScanSize`, `MaxFileSize`, `MaxRecursion`, `MaxFiles` กับเวอร์ชันที่ใช้งาน และทดสอบ archive bomb ก่อนเปิดสู่ภายนอก
- YARA rules ที่ให้มาคือ heuristic ตัวอย่างสำหรับ PowerShell download/decode/execute และ JavaScript decode/dynamic execution; เงื่อนไขต้องพบสัญญาณที่สัมพันธ์กันมากกว่าหนึ่งกลุ่ม ไม่ใช่ signature ครบถ้วน และผลตรงกฎไม่ใช่ข้อสรุปว่าเป็นมัลแวร์
- อย่าเพิ่มตัวอย่างเงื่อนไขทั่วไป เช่น `($abc or not $abc)` หรือกฎที่จับเพียงขนาดไฟล์ลงชุด production เพราะอาจ match ไฟล์ทั่วไปจำนวนมากและสร้าง false positive
- หน้าเว็บใช้ Firebase Authentication สำหรับเข้าสู่ระบบและสร้างบัญชีด้วยอีเมล; `login.html` เป็นหน้าแยก และ `index.html` เปลี่ยนเส้นทางไปหน้าเข้าสู่ระบบเมื่อไม่มี session. File upload, ผลสแกนใหม่, website-header check และ Wi-Fi report ตรวจ Firebase ID token; ผลสแกนใหม่ผูกกับ UID ผู้สร้างและมี Redis per-user rate limit. Scan เก่าก่อน migration ยังคงใช้ capability token. ให้คง API หลัง Tailscale/private network และห้ามเปิดพอร์ตสู่ public internet จนกว่าจะทำ public-deployment review ครบ
- อย่าเก็บไฟล์ที่ตรวจพบไว้ให้ผู้ใช้ดาวน์โหลดจากเว็บ; รายงานเก็บเฉพาะ hash, metadata, findings และ remediation

## 6. การสแกนไฟล์ในเครื่องและผ่าน Backend

**ไม่อัปโหลดไฟล์:** บน Windows ที่ Microsoft Defender Antivirus เปิดใช้งาน ให้ดาวน์โหลด `virus-scan.ps1` จากหน้าเว็บ แล้วเรียก PowerShell ด้วย `-ExecutionPolicy Bypass` สำหรับการเรียกครั้งนั้น เลือกไฟล์จากหน้าต่างที่เปิดขึ้น และนำเข้า `virus-scan-report.json` ในหน้าเว็บ หาก Defender ปิดใช้งาน ตัวช่วยจะหยุดก่อนเลือกไฟล์และไม่รายงานผลว่าไฟล์สะอาด ทั้งนี้ Defender อาจกักกัน/ลบไฟล์ตามการตั้งค่าของระบบ

**สแกนผ่าน Backend:** ต้องติดตั้ง Docker Desktop พร้อม Docker Compose จากนั้นเปิด PowerShell ในโฟลเดอร์โปรเจกต์และเรียก:

```powershell
docker compose up --build
```

เปิด `http://localhost:8000` แล้วเลือกเมนู **สแกนไวรัส** และใช้เฉพาะส่วน Backend เมื่อต้องการส่งไฟล์เข้า quarantine เพื่อให้ ClamAV/YARA ตรวจ ระบบจะดาวน์โหลด image และฐานข้อมูล ClamAV ในการเริ่มครั้งแรก ซึ่งอาจใช้เวลาหลายนาที ตรวจสุขภาพบริการได้ที่ `http://localhost:8000/api/v1/health` และ API docs อยู่ที่ `http://localhost:8000/api/docs`

หยุดระบบด้วย `Ctrl+C`; ใช้ `docker compose down` เพื่อหยุดและคงข้อมูล volume ไว้ อย่าใช้ `docker compose down -v` หากต้องการเก็บฐานข้อมูลและ signature cache

ค่า `POSTGRES_PASSWORD` เริ่มต้นใน Compose มีไว้สำหรับการพัฒนาในเครื่องเท่านั้น API ที่รับข้อมูลสแกนตรวจ Firebase ID token และจำกัดอัตราคำขอต่อผู้ใช้ แต่ยังไม่มี email verification, quota/retention, monitoring, backups และ external security review ครบถ้วน อย่าเปิด API ให้เข้าถึงจากเครือข่ายสาธารณะ

### Firebase Authentication ในหน้าเว็บและ API

หน้าเว็บใช้ Firebase Authentication SDK สำหรับเข้าสู่ระบบและสร้างบัญชีด้วยอีเมลและรหัสผ่าน หน้าเข้าสู่ระบบอยู่ใน `login.html`; หน้าเว็บหลักใน `index.html` ตรวจสถานะ session และเปลี่ยนเส้นทางผู้ใช้ที่ยังไม่เข้าสู่ระบบ โดย config ของ Firebase Web App อยู่ในทั้งสองไฟล์และเป็น client config ไม่ใช่ service-account credential ใน Firebase Console ต้องเปิด Email/Password provider และเพิ่ม domain ที่ใช้โฮสต์ไว้ใน Authorized domains endpoint สำหรับอัปโหลดไวรัส, ตรวจเว็บไซต์, รายงาน Wi-Fi และ AI ต้องตรวจ Firebase ID token; scan ใหม่ผูกกับ UID ของผู้ใช้ ส่วน scan เก่าก่อน migration ใช้ capability token เดิม การเปลี่ยนเส้นทางหน้าเว็บ การซ่อนปุ่ม หรือการตั้ง CORS ไม่ใช่ authorization

การส่งรายงาน Wi-Fi เป็น opt-in โดย checkbox; backend ตรวจ schema และส่งผลกลับโดยไม่บันทึก SSID หรือรายงานลงฐานข้อมูล หากไม่ยินยอม รายงานจะถูกวิเคราะห์ใน browser เท่านั้น ต้องตั้ง `FIREBASE_PROJECT_ID` ให้ตรงกับ Firebase Web App ก่อนใช้ endpoint นี้

GitHub Pages ให้บริการเฉพาะไฟล์ static; ค่าเริ่มต้นของ `scanner-api-base` ว่าง หน้าเว็บจึงไม่ส่ง health request และแจ้งว่าไม่มี Backend ส่วนตัวช่วย Defender/Wi-Fi ทำงานบนเครื่องได้ และลิงก์ดาวน์โหลดเป็น relative URL เพื่อรองรับ project site เช่น `/S/`. เมื่อ deploy API ส่วนตัวแล้ว สามารถตั้งค่าเป็น HTTPS origin จาก Tailscale Serve ตาม [คู่มือ deploy](./DEPLOY-PRIVATE-VPS.md); browser จะเรียก API ข้าม origin และ CORS อนุญาตเฉพาะ origin ที่กำหนดไว้ CORS ไม่ใช่ authorization และห้ามเปิด API ผ่าน Tailscale Funnel หรือ public reverse proxy

ดูขั้นตอนติดตั้ง backend บน VPS และเชื่อม GitHub Pages ผ่าน Tailscale HTTPS ใน [DEPLOY-PRIVATE-VPS.md](./DEPLOY-PRIVATE-VPS.md). CORS allowlist ตั้งผ่าน `CORS_ORIGINS`; ค่าเริ่มต้นอนุญาตเฉพาะ `https://funnythirat.github.io` แต่ CORS ไม่ใช่ authentication และ API ต้องคงอยู่หลัง Tailscale Serve โดยไม่เปิด Tailscale Funnel

### Deploy แบบ private บน VPS ผ่าน Tailscale

ไฟล์ `docker-compose.production.yml` เป็น override สำหรับ VPS โดยบังคับตั้ง `POSTGRES_PASSWORD` และให้ API/worker รอ PostgreSQL กับ Redis ผ่าน health check ก่อนเริ่มงาน เริ่มด้วย Linux VPS ที่ติดตั้ง Docker Engine, Compose Plugin และ Tailscale แล้ว:

1. ส่งเฉพาะ source ที่จำเป็นขึ้น VPS: `Dockerfile`, `docker-compose.yml`, `docker-compose.production.yml`, `requirements.txt`, `index.html`, `wifi-scan.ps1`, `virus-scan.ps1` และโฟลเดอร์ `backend`. ห้ามส่ง `.env` จากเครื่องพัฒนา, diagnostics bundle หรือไฟล์ secret
2. ในโฟลเดอร์โปรเจกต์บน VPS สร้าง `.env` ที่มีเฉพาะรหัสผ่านฐานข้อมูล production สุ่มแบบ hex และจำกัดสิทธิ์ไฟล์:

   ```bash
   umask 077
   printf 'POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 32)" > .env
   chmod 600 .env
   ```

   เก็บรหัสผ่านนี้ใน password manager/secret manager และอย่าเปลี่ยนค่าระหว่างใช้งานฐานข้อมูลเดิม มิฉะนั้น PostgreSQL ที่สร้างไว้แล้วจะไม่เปลี่ยนรหัสผ่านตาม environment โดยอัตโนมัติ
3. ตรวจ merged Compose โดยไม่แสดง environment values แล้วเริ่มบริการ:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.production.yml config --quiet
   docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --build
   docker compose -f docker-compose.yml -f docker-compose.production.yml ps
   ```
4. ตรวจสุขภาพจาก VPS เอง:

   ```bash
   curl --fail http://127.0.0.1:8000/api/v1/health
   ```

   ก่อนแชร์เว็บ ต้องเห็น `status` เป็น `ready` และทุก service เป็น `true`
5. ติดตั้ง/ล็อกอิน Tailscale บน VPS และอุปกรณ์ของผู้ใช้ จำกัด tailnet access ให้เฉพาะคนหรืออุปกรณ์ที่อนุญาต จากนั้นบน VPS รัน `tailscale serve 8000` เพื่อให้บริการผ่าน HTTPS ภายใน tailnet เท่านั้น ใช้ URL ที่ Tailscale แสดง ห้ามเปิด Tailscale Funnel, พอร์ต `8000`, PostgreSQL, Redis หรือ ClamAV สู่ public internet
6. ทดสอบจากอุปกรณ์ที่อนุญาตและเชื่อม Tailscale แล้วเปิด URL ที่ Serve แสดง ตรวจ health และทดสอบ scan ไฟล์ที่ไม่มีข้อมูลลับ จากนั้นยืนยันว่ารายงานสำเร็จและไฟล์ quarantine ชั่วคราวถูกลบ

การจำกัดด้วย Tailscale เป็นขอบเขตการเข้าถึงของ deployment ส่วนตัว ไม่ใช่ระบบบัญชีผู้ใช้ของแอป ผู้ที่อยู่ใน tailnet และมีสิทธิ์เข้าถึง URL สามารถใช้ API สแกนได้ จึงควรเชิญเฉพาะผู้ใช้ที่ไว้ใจ ตรวจ Tailscale ACL/device approval และสำรอง volume `postgres_data`, `clamav_data` และ `quarantine` อย่างปลอดภัย ก่อนเปิดให้บุคคลทั่วไปหรือกลุ่มที่ไม่ไว้ใจใช้ ต้องเพิ่ม authentication/authorization, per-user ownership, rate limits, retention controls และ production security review ก่อน

รันชุดทดสอบ backend ใน PowerShell ด้วย:

```powershell
python -m pip install -r requirements-dev.txt
$env:PYTHONPATH = "backend"
python -m unittest discover -s backend\tests -v
```

### API, ข้อมูล และการตรวจสอบ

- บังคับ HTTPS, authentication, authorization แบบตรวจเจ้าของ asset/scan ทุก request และ rate limit
- ใช้ CSRF protection หากใช้ cookie-based session; ใช้ CORS allowlist ที่แคบ
- ตรวจ input ด้วย schema และปฏิเสธค่าที่ไม่ได้ระบุ; ห้ามแสดงรายละเอียด exception หรือ stack trace ต่อผู้ใช้
- เข้ารหัสข้อมูลสำคัญเมื่อจัดเก็บ, จัดการ secret ผ่าน environment/secret manager และใช้ least privilege
- บันทึก audit event ของผู้สร้างงาน, asset, เวลา และผลสถานะ โดยไม่บันทึก token หรือข้อมูลลับ
- กำหนด retention และการลบข้อมูลให้ชัดเจน พร้อมสำรองและทดสอบการกู้คืนฐานข้อมูล

## 7. โครงสร้างโค้ดที่แนะนำ

```text
app/
  api/
    routes/
      assets.py
      scans.py
      findings.py
  core/
    config.py
    auth.py
    scope_policy.py
  db/
    models.py
    session.py
  schemas/
    asset.py
    scan.py
    finding.py
  services/
    scan_service.py
    report_service.py
  workers/
    celery_app.py
    tasks.py
    scanners/
      http_headers.py
      tls_certificate.py
      dependencies.py
      source_code.py
tests/
  api/
  workers/
  security/
```

Frontend แยกหน้าเข้าสู่ระบบ (`login.html`) ออกจากหน้าเว็บหลัก (`index.html`) และยังใช้ JavaScript/CSS ภายใน HTML; สามารถแยก asset ออกเป็นไฟล์เมื่อเริ่มเพิ่มการทดสอบและฟีเจอร์

## 8. แผนพัฒนาต่อและเกณฑ์รับงาน

### ระยะ 1 — พื้นฐานระบบ

- สร้าง FastAPI, PostgreSQL schema และ migration
- เพิ่ม authentication, ownership checks, asset allowlist และ audit log
- ตั้งค่า Docker Compose สำหรับ API, PostgreSQL, Redis และ worker ในสภาพแวดล้อมพัฒนา

**เกณฑ์รับงาน:** ผู้ใช้ไม่สามารถอ่าน asset หรือ scan ของผู้ใช้อื่นได้; API ปฏิเสธ target ที่ไม่ได้ลงทะเบียน

### ระยะ 2 — Queue และสถานะงาน

- เพิ่ม Celery task, สถานะงาน, timeout, retry policy และ polling endpoint
- เพิ่ม quota/concurrency limit และการ recover งานค้าง

**เกณฑ์รับงาน:** API ตอบกลับการสร้างงานได้โดยไม่รอ scanner; งานที่จบแล้วมีสถานะและเวลาแน่นอน; งานล้มเหลวไม่แสดงผลสำเร็จปลอม

### ระยะ 3 — Passive HTTP/TLS

- ทำ HTTP `HEAD` check และประเมิน security headers
- ตรวจ TLS certificate ด้วย hostname validation และบันทึกวันหมดอายุ/ผลตรวจ
- ใช้ DNS/IP validation, redirect policy และ egress restriction ก่อนเปิด worker

**เกณฑ์รับงาน:** ทดสอบกรณี private IP, localhost, metadata IP, DNS rebinding และ redirect ออกนอก allowlist แล้วต้องถูกปฏิเสธ

### ระยะ 4 — Dependency และ Source Code

- รองรับ lockfile ก่อน manifest เพื่อให้ได้เวอร์ชัน dependency ที่แน่นอน
- ส่งข้อมูลขั้นต่ำที่จำเป็นไปยัง OSV; ระบุแหล่งข้อมูลและเวลาที่ตรวจในรายงาน
- เพิ่ม static analysis ใน sandbox ที่ไม่ execute โค้ด และกำหนดขนาด/จำนวนไฟล์

**เกณฑ์รับงาน:** ทดสอบ package ที่รู้ว่ามี advisory และ package ที่ไม่มี advisory; ทดสอบไฟล์เสีย, ไฟล์ใหญ่ และไฟล์จำนวนมาก

### ระยะ 4A — Virus scanning (implemented)

- API ส่งไฟล์เข้า quarantine และให้ Celery worker สแกนด้วย ClamAV ผ่าน clamd socket; โหมดลึกเพิ่ม YARA heuristic
- API แสดง verdict, hash, engine, ข้อจำกัด และคำแนะนำ; worker ลบไฟล์ quarantine เมื่อ scan จบและเก็บไฟล์ไว้ระหว่าง retry
- มี unit tests สำหรับ ClamAV response, YARA fixtures, upload limits และ retry; ควรทดสอบ EICAR, archive เสีย และการฟื้นตัวจาก worker/daemon failure ในสภาพแวดล้อม Docker ก่อน production

**เกณฑ์รับงาน:** ทั้งสองโหมดให้สถานะ `queued/running/completed/failed` ถูกต้อง; ไฟล์ชั่วคราวถูกลบเมื่อจบงาน; การตรวจที่ engine ไม่พร้อมต้อง retry ตามจำนวนครั้งที่กำหนดและสุดท้ายแสดง error ไม่แสดงผล clean

### ระยะ 5 — Dashboard และรายงาน

- เชื่อม frontend กับ API, แสดงสถานะและ severity breakdown
- เพิ่ม filter, pagination, รายละเอียด finding, remediation และ JSON export
- เพิ่ม retention, backup, monitoring และ alert สำหรับ worker ค้างหรือ queue โตผิดปกติ

**เกณฑ์รับงาน:** รายงานตรงกับข้อมูลในฐานข้อมูล, severity ไม่ถูกแต่งขึ้น, UI รองรับ loading/empty/error states และผู้ใช้เห็นเฉพาะรายงานของตน

## 9. ข้อเสนอแนะสำหรับการพัฒนาต่อ

ต้นแบบมี Firebase authentication/token verification, owner scoping สำหรับ scan ใหม่, และ Redis per-user rate limits สำหรับ API หลักแล้ว แต่ยังไม่พร้อมเปิด public โดยไม่จำกัด ก่อนให้ผู้ใช้นอก trusted tailnet เข้าถึง ต้องเพิ่ม email verification, quota/retention, monitoring/alerts, backup/restore drills, rate-limit และ resource-limit review, TLS/reverse proxy deployment, และ security review รวมทั้งทบทวน egress/network isolation และ resource limits ของ ClamAV/YARA worker. ต้อง apply database migration ก่อน deploy code ที่เพิ่ม owner UID

เครื่องมือนี้เป็นตัวช่วยคัดกรอง ไม่ใช่การรับรองว่าระบบปลอดภัย การนำไปใช้งานจริงควรมีผู้รับผิดชอบด้านความปลอดภัยตรวจสอบ scope, network egress และการจัดการข้อมูลก่อนเปิดให้ผู้ใช้เข้าถึง

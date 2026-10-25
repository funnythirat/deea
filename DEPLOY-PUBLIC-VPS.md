# คู่มือการติดตั้ง Backend ขึ้น Cloud VPS สำหรับการใช้งานจริงแบบสาธารณะ 24 ชั่วโมง

คู่มือนี้แนะนำขั้นตอนการนำระบบ Backend (FastAPI, Celery, ClamAV, YARA, PostgreSQL, Redis) ขึ้นสู่ **Cloud Server (VPS)** พร้อมระบบ **HTTPS อัตโนมัติ (Caddy / Let's Encrypt)** เพื่อให้ทุกคนบนอินเทอร์เน็ตสามารถเปิดเข้าหน้าเว็บ GitHub Pages และใช้งานฟังก์ชันสแกนไฟล์หาไวรัสและตรวจเว็บไซต์ได้อย่างเต็มรูปแบบตลอด 24 ชั่วโมง

---

## 1. การเลือกและเตรียม VPS (Server)

### สเปกเครื่องที่แนะนำ
- **CPU:** 2 vCPU ขึ้นไป
- **RAM:** แนะนำ **2 GB - 4 GB** (ClamAV ใช้ RAM ประมาณ 1.2 - 1.5 GB สำหรับโหลดฐานข้อมูล Signature ไวรัส)
- **Disk:** 30 GB SSD ขึ้นไป
- **OS:** **Ubuntu 22.04 LTS** หรือ **Ubuntu 24.04 LTS** (64-bit)

### ผู้ให้บริการ VPS แนะนำ (เลือกเจ้าใดก็ได้):
1. **DigitalOcean:** Droplet รุ่น Basic ($12 - $18/เดือน ได้ RAM 2GB-4GB)
2. **Hetzner Cloud:** รุ่น CX22 หรือ CPX21 (~€4 - €8/เดือน คุ้มค่าที่สุด)
3. **VPS ในไทย (เช่น Bangmod, Hostatom, Ruk-Com):** (~200 - 450 บาท/เดือน ได้ความเร็วเชื่อมต่อในประเทศสูง)

---

## 2. การเตรียม Domain Name และ HTTPS

เพื่อให้เบราว์เซอร์ของคนอื่นเรียกใช้ Backend จากหน้าเว็บ GitHub Pages ได้อย่างราบรื่น **Backend ต้องมีโดเมนและเป็น HTTPS**:

1. **กรณีมีโดเมนของตนเอง (เช่น `yourdomain.com`):**
   - ไปที่ DNS Management ของโดเมนคุณ
   - เพิ่ม **A Record** ชื่อย่อย เช่น `api` ชี้ไปยัง **IPv4 Address ของ VPS**
   - ตัวอย่าง: `api.yourdomain.com` -> `123.45.67.89`

2. **กรณีต้องการใช้โดเมนฟรี (เช่น DuckDNS):**
   - สมัครใช้งานฟรีที่ [duckdns.org](https://www.duckdns.org)
   - สร้าง sub-domain เช่น `deea-scanner.duckdns.org`
   - ใส่ **IP ของ VPS** ในช่อง IP แล้วกด update ip

---

## 3. ขั้นตอนติดตั้งบน VPS (เพียง 1 คำสั่ง)

1. **เข้าสู่ VPS ผ่าน Terminal / SSH:**
   ```bash
   ssh root@<IP-ของ-VPS>
   ```

2. **ดาวน์โหลดโปรเจกต์ลงบน VPS:**
   ```bash
   sudo git clone https://github.com/funnythirat/deea.git /opt/deea
   cd /opt/deea
   ```

3. **รันสคริปต์ติดตั้งอัตโนมัติ:**
   ```bash
   sudo chmod +x setup-vps.sh
   sudo ./setup-vps.sh
   ```

4. สคริปต์จะทำงานโดยอัตโนมัติ:
   - สร้าง Swapfile 2GB ป้องกัน Memory เต็ม
   - ติดตั้ง Docker & Docker Compose
   - ตั้งค่า Firewall UFW (เปิดเฉพาะพอร์ต 22, 80, 443)
   - สุ่มสร้างรหัสผ่าน Database อย่างปลอดภัย
   - สอบถามชื่อ Domain ที่คุณเตรียมไว้ (เช่น `api.yourdomain.com` หรือ `deea-scanner.duckdns.org`)
   - ขอใบรับรองความปลอดภัย **HTTPS (SSL Certificate)** ให้อัตโนมัติผ่าน Caddy
   - รัน Database Migration และตรวจสอบความพร้อมของระบบ

---

## 4. เชื่อมโยงหน้าเว็บ GitHub Pages เข้ากับ Backend

เมื่อสคริปต์บน VPS ติดตั้งสำเร็จ:
1. เปิดไฟล์ `index.html` ในเครื่องคอมพิวเตอร์ของคุณ
2. แก้ไขบรรทัดที่ 7 ให้ใส่ URL ของโดเมนใหม่:
   ```html
   <meta name="scanner-api-base" content="https://api.yourdomain.com">
   ```
   *(เปลี่ยน `https://api.yourdomain.com` เป็นโดเมนจริงของคุณ)*
3. บันทึกไฟล์ และส่งขึ้น GitHub:
   ```bash
   git add index.html
   git commit -m "Connect frontend to public production backend"
   git push origin main
   ```

4. เปิดหน้าเว็บ GitHub Pages (`https://funnythirat.github.io/deea/`):
   - ไฟสถานะ Backend มุมบนจะเปลี่ยนเป็น **"พร้อมใช้งาน" (สีเขียว)**
   - ทุกคนที่เข้ามาใช้งานเว็บจะสามารถอัปโหลดสแกนไวรัส ClamAV/YARA ได้ทันทีจากทุกที่!

---

## 5. คำสั่งดูแลรักษาระบบบน VPS

- **ตรวจสอบสถานะบริการทั้งหมด:**
  ```bash
  cd /opt/deea
  docker compose ps
  ```

- **ดู Log การทำงานแบบ Real-time:**
  ```bash
  docker compose -f docker-compose.yml -f docker-compose.production.yml -f docker-compose.public.yml logs -f api
  ```

- **อัปเดตโค้ดเป็นเวอร์ชันใหม่ล่าสุดในอนาคต:**
  ```bash
  cd /opt/deea
  sudo git pull
  sudo docker compose -f docker-compose.yml -f docker-compose.production.yml -f docker-compose.public.yml up -d --build
  ```

- **รีสตาร์ทระบบ:**
  ```bash
  sudo docker compose -f docker-compose.yml -f docker-compose.production.yml -f docker-compose.public.yml restart
  ```

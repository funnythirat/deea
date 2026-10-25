#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Automated VPS Setup Script for "วิถีป้องกันรอบด้าน" Security Scanner
# Tested on: Ubuntu 22.04 LTS / 24.04 LTS
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
  echo "[-] กรุณารันสคริปต์นี้ด้วยสิทธิ์ root (sudo ./setup-vps.sh)"
  exit 1
fi

echo "=========================================================="
echo "  กำลังเริ่มต้นติดตั้งระบบ Security Scanner บน VPS"
echo "=========================================================="

# 1. จัดการ Swapfile 2GB ป้องกัน ClamAV Memory Overflow
if [ ! -f /swapfile ]; then
  echo "[+] กำลังสร้าง Swap ขนาด 2GB สำหรับ ClamAV signature database..."
  fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo "[+] สร้าง Swap สำเร็จ"
else
  echo "[*] พบ Swapfile อยู่แล้ว ข้ามขั้นตอนนี้"
fi

# 2. ติดตั้ง Docker และ Docker Compose หากยังไม่มี
if ! command -v docker &> /dev/null; then
  echo "[+] กำลังติดตั้ง Docker Engine และ Docker Compose..."
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg lsb-release ufw

  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
  echo "[+] ติดตั้ง Docker สำเร็จ"
else
  echo "[*] พบ Docker ติดตั้งอยู่แล้ว"
fi

# 3. ตั้งค่า Firewall (เปิดเฉพาะ SSH, HTTP, HTTPS)
echo "[+] กำลังตรวจสอบและตั้งค่า Firewall (UFW)..."
ufw allow 22/tcp || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw --force enable || true

# 4. ตั้งค่าไฟล์สภาพแวดล้อม (.env)
ENV_FILE=".env"
if [ ! -f "$ENV_FILE" ]; then
  echo "[+] กำลังสร้างไฟล์ .env ใหม่..."
  PG_PASS=$(openssl rand -hex 32)
  cat <<EOF > "$ENV_FILE"
POSTGRES_PASSWORD=$PG_PASS
DOMAIN=
ACME_EMAIL=admin@example.com
CORS_ORIGINS=https://funnythirat.github.io
FIREBASE_PROJECT_ID=deea-9ed32
MAX_UPLOAD_BYTES=20971520
EOF
  chmod 600 "$ENV_FILE"
fi

# ตรวจสอบการตั้งค่า DOMAIN
DOMAIN_SETTING=$(grep -E "^DOMAIN=" "$ENV_FILE" | cut -d'=' -f2- || true)
if [ -z "$DOMAIN_SETTING" ]; then
  echo ""
  echo "----------------------------------------------------------"
  echo "กรุณาระบุ Domain Name ที่ชี้ A Record มายัง IP ของ VPS เครื่องนี้"
  echo "เช่น: api.yourdomain.com หรือ deea-api.duckdns.org"
  read -rp "โดเมนของคุณ: " USER_DOMAIN
  USER_DOMAIN=$(echo "$USER_DOMAIN" | tr -d ' ')
  if [ -z "$USER_DOMAIN" ]; then
    echo "[-] จำเป็นต้องระบุ Domain เพื่อขอใบรับรอง HTTPS อัตโนมัติ"
    exit 1
  fi
  sed -i "s|^DOMAIN=.*|DOMAIN=$USER_DOMAIN|" "$ENV_FILE"
fi

ACTIVE_DOMAIN=$(grep -E "^DOMAIN=" "$ENV_FILE" | cut -d'=' -f2-)
echo "[*] ใช้งานโดเมน: $ACTIVE_DOMAIN"

# 5. สตาร์ท Stack ผ่าน Docker Compose
echo "[+] กำลัง Build และเริ่มรันบริการทั้งหมด (API, Worker, DB, Redis, ClamAV, Caddy)..."
docker compose -f docker-compose.yml -f docker-compose.production.yml -f docker-compose.public.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.production.yml -f docker-compose.public.yml up -d --build

# 6. รัน Database Migration
echo "[+] รอ Database พร้อมทำงานและรัน Migration..."
docker compose exec -T db sh -c 'until pg_isready -U scanner -d scanner; do sleep 2; done'
docker compose -f docker-compose.yml -f docker-compose.production.yml exec -T db \
  psql -U scanner -d scanner < backend/migrations/0001_add_scan_ownership.sql || true

# 7. รอตรวจ Health Check
echo "[+] กำลังตรวจสอบสถานะระบบ (รอ ClamAV และ Services โหลดข้อมูล)..."
ATTEMPTS=0
MAX_ATTEMPTS=20
HEALTHY=false

while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
  if curl -sf http://127.0.0.1:8000/api/v1/health | grep -q '"status":"ready"'; then
    HEALTHY=true
    break
  fi
  echo -n "."
  sleep 6
  ATTEMPTS=$((ATTEMPTS+1))
done
echo ""

if [ "$HEALTHY" = true ]; then
  echo "=========================================================="
  echo "  [SUCCESS] ติดตั้งและเริ่มการทำงานสำเร็จสมบูรณ์!"
  echo "=========================================================="
  echo "Backend API เปิดให้บริการผ่าน HTTPS แล้วที่:"
  echo "  https://$ACTIVE_DOMAIN"
  echo ""
  echo "ขั้นตอนสุดท้ายเพื่อเปิดใช้งานบนหน้าเว็บ GitHub Pages:"
  echo "1. เปิดไฟล์ index.html ในโปรเจกต์ของคุณ"
  echo "2. อัปเดตบรรทัดที่ 7:"
  echo "   <meta name=\"scanner-api-base\" content=\"https://$ACTIVE_DOMAIN\">"
  echo "3. ทำการ commit และ push ขึ้น GitHub"
  echo "4. เมื่อเปิดหน้าเว็บ GitHub Pages ทุกคนจะเชื่อมต่อ Backend ได้ทันที!"
  echo "=========================================================="
else
  echo "[!] ระบบเริ่มทำงานแล้ว แต่บางส่วน (เช่น ClamAV) อาจยังดาวน์โหลดฐานข้อมูลไวรัสอยู่"
  echo "คุณสามารถเช็คสถานะได้ด้วยคำสั่ง:"
  echo "  docker compose ps"
  echo "  curl http://127.0.0.1:8000/api/v1/health"
fi

import { initializeApp } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-app.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-auth.js";

"use strict";

const firebaseConfig = {
  apiKey: "AIzaSyAjyXKgx8Ox-s9tBsP2w2psXWM0EVUJCOk",
  authDomain: "deea-9ed32.firebaseapp.com",
  projectId: "deea-9ed32",
  storageBucket: "deea-9ed32.firebasestorage.app",
  messagingSenderId: "649361533233",
  appId: "1:649361533233:web:a2f979984a76f67f222810"
};
const auth = getAuth(initializeApp(firebaseConfig));

const state = {
  scans: 0,
  findings: 0,
  high: 0,
  medium: 0,
  low: 0,
  last: null,
  history: [],
  virusJobs: new Map()
};
const titles = {
  dashboard: "ภาพรวมความปลอดภัย",
  queue: "คิวงานสแกน",
  reports: "ประวัติและรายงาน",
  engines: "Scanning Engines",
  virus: "สแกนไวรัส",
  wifi: "ตรวจสอบ Wi-Fi",
  website: "ตรวจการตั้งค่าเว็บไซต์",
  code: "วิเคราะห์ซอร์สโค้ด",
  dependencies: "ตรวจสอบ Dependency"
};
const navButtons = document.querySelectorAll("[data-view]");
const configuredApiBase = document.querySelector('meta[name="scanner-api-base"]').content.trim();
const isGitHubPages = location.hostname.endsWith(".github.io");
const isLocalBackend = ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
const apiBase = isLocalBackend
  ? location.origin
  : configuredApiBase
  ? new URL(configuredApiBase, location.href).href.replace(/\/+$/, "")
  : isGitHubPages || location.protocol === "file:"
    ? null
    : location.origin;

const LEGACY_WIFI_AUTHENTICATION = ["SHARED", "WPA-NONE"];
const WPA1_AUTHENTICATION = ["WPA", "WPA-PSK", "WPA-PERSONAL", "WPA-ENTERPRISE"];

function apiUrl(path) {
  if (!apiBase) return null;
  return apiBase + "/api/v1/" + path.replace(/^\/+/, "");
}

async function authenticatedApiFetch(path, options = {}) {
  const user = auth.currentUser;
  if (!user) throw new Error("กรุณาเข้าสู่ระบบก่อนเชื่อมต่อ Backend");
  const token = await user.getIdToken();
  const headers = new Headers(options.headers || {});
  headers.set("Authorization", "Bearer " + token);
  return fetch(apiUrl(path), { ...options, headers });
}

function showView(name) {
  document.querySelectorAll(".view").forEach((view) => view.classList.toggle("active", view.id === "view-" + name));
  navButtons.forEach((button) => {
    if (button.dataset.view === name) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  document.getElementById("pageTitle").textContent = titles[name];
}
navButtons.forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
document.querySelectorAll("[data-go]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.go)));

// --- Interactive Wi-Fi Network Picker & Security Inspector ---
const SAMPLE_WIFI_NETWORKS = [
  {
    ssid: "Home_FastWiFi_5G",
    signalQualityPercent: 96,
    authentication: "WPA2-PSK",
    cipher: "AES-CCMP",
    hasPassword: true,
    isConnected: true,
    capturedAtUtc: new Date().toISOString()
  },
  {
    ssid: "TrueWiFi_Free_Guest",
    signalQualityPercent: 82,
    authentication: "OPEN",
    cipher: "NONE",
    hasPassword: false,
    isConnected: false,
    capturedAtUtc: new Date().toISOString()
  },
  {
    ssid: "AIS_Smart_5G_Home",
    signalQualityPercent: 78,
    authentication: "WPA3-SAE",
    cipher: "GCMP-256",
    hasPassword: true,
    isConnected: false,
    capturedAtUtc: new Date().toISOString()
  },
  {
    ssid: "CoffeeCorner_FreeWiFi",
    signalQualityPercent: 65,
    authentication: "OPEN",
    cipher: "NONE",
    hasPassword: false,
    isConnected: false,
    capturedAtUtc: new Date().toISOString()
  },
  {
    ssid: "Office_Enterprise_Secure",
    signalQualityPercent: 58,
    authentication: "WPA2-ENTERPRISE",
    cipher: "AES-CCMP",
    hasPassword: true,
    isConnected: false,
    capturedAtUtc: new Date().toISOString()
  },
  {
    ssid: "Apartment_Old_Router",
    signalQualityPercent: 44,
    authentication: "WEP",
    cipher: "WEP40",
    hasPassword: true,
    isConnected: false,
    capturedAtUtc: new Date().toISOString()
  },
  {
    ssid: "3BB_Fiber_Old_WPA",
    signalQualityPercent: 32,
    authentication: "WPA-PSK",
    cipher: "TKIP",
    hasPassword: true,
    isConnected: false,
    capturedAtUtc: new Date().toISOString()
  }
];

let activeWifiList = [];
let selectedWifiNetwork = null;

function evaluateWifiSecurity(network) {
  const auth = (network.authentication || "UNKNOWN").toUpperCase();
  const cipher = (network.cipher || "UNKNOWN").toUpperCase();
  const hasPassword = network.hasPassword !== undefined
    ? Boolean(network.hasPassword)
    : (!auth.includes("OPEN") && !auth.includes("NONE") && cipher !== "NONE");

  const isWep = auth.includes("WEP") || cipher.includes("WEP");
  const isWpa1 = WPA1_AUTHENTICATION.includes(auth) || cipher === "TKIP";
  const isWpa3 = auth.includes("WPA3");
  const isWpa2 = auth.includes("WPA2") || auth === "WPA2-PSK";

  let grade = "secure"; // "secure", "warning", "danger"
  let icon = "🔒";
  let title = "";
  let description = "";
  const findings = [];
  const recs = [];

  if (!hasPassword) {
    grade = "danger";
    icon = "🔓";
    title = "เสี่ยงอันตรายสูงสุด: สัญญาณนี้ไม่มีรหัสผ่าน (Open Network)";
    description = "เครือข่ายนี้ไม่มีการตั้งรหัสผ่านและไม่มีการเข้ารหัสข้อมูล (Unencrypted) ทุกคนสามารถเชื่อมต่อได้ทันที และผู้โจมตีที่อยู่ในระยะสัญญาณสามารถดักจับข้อมูล (Packet Sniffing) หรือดักอ่านรหัสผ่านและข้อความได้โดยง่าย";
    findings.push({
      level: "high",
      title: "เครือข่ายเปิด (ไม่มีรหัสผ่าน)",
      detail: "ข้อมูลที่ส่งผ่าน Wi-Fi นี้ไม่มีการเข้ารหัสระดับชั้นสัญญาณ อาจถูกดักจับและปลอมแปลงการเชื่อมต่อได้"
    });
    recs.push("❌ หลีกเลี่ยงการเปิดใช้งานแอพธนาคาร หรือทำธุรกรรมการเงินบนเครือข่ายนี้อย่างเด็ดขาด");
    recs.push("❌ ไม่ล็อกอินเข้าสู่ระบบหรือเว็บไซต์ที่ไม่ได้ใช้ HTTPS");
    recs.push("🛡️ หากจำเป็นต้องใช้งาน แนะนำให้เปิดเชื่อมต่อผ่าน VPN ที่น่าเชื่อถือเสมอ");
  } else if (isWep) {
    grade = "danger";
    icon = "⚠️";
    title = "เสี่ยงสูงมาก: มาตรฐาน WEP ล้าสมัยและถูกถอดรหัสได้ง่าย";
    description = "เครือข่ายนี้ใช้ระบบ WEP ซึ่งเป็นมาตรฐานเก่าตั้งแต่ปี 1999 ที่มีช่องโหว่ทางคณิตศาสตร์ สามารถถูกแคร็กรหัสผ่านได้ภายในไม่กี่นาที";
    findings.push({
      level: "high",
      title: "พบการเข้ารหัส WEP ที่เลิกใช้งานแล้ว",
      detail: "WEP มีความปลอดภัยไม่เพียงพออย่างยิ่ง ควรเปลี่ยนการตั้งค่าเราเตอร์เป็น WPA2-AES หรือ WPA3"
    });
    recs.push("เปลี่ยนการตั้งค่า Security Mode บน Router ให้เป็น WPA2-AES หรือ WPA3 ทันที");
    recs.push("ไม่ควรเชื่อมต่ออุปกรณ์ที่มีข้อมูลสำคัญกับ Wi-Fi ที่ใช้ WEP");
  } else if (isWpa1) {
    grade = "warning";
    icon = "⚠️";
    title = "เสี่ยงปานกลาง: ใช้ WPA รุ่นเก่า หรือการเข้ารหัส TKIP";
    description = "มีรหัสผ่าน แต่ใช้มาตรฐาน WPA รุ่นแรกหรือการเข้ารหัส TKIP ซึ่งมีความแข็งแกร่งต่ำกว่ามาตรฐานปัจจุบัน";
    findings.push({
      level: "medium",
      title: "ใช้การยืนยันตัวตนหรือการเข้ารหัสแบบเก่า (WPA/TKIP)",
      detail: "ควรเปลี่ยนการตั้งค่าเราเตอร์เป็น WPA2-AES หรือ WPA3"
    });
    recs.push("ปรับเปลี่ยนการเข้ารหัสบนเราเตอร์จาก TKIP ให้เป็น AES/CCMP");
  } else if (isWpa3) {
    grade = "secure";
    icon = "🛡️";
    title = "ปลอดภัยระดับสูงสุด: ป้องกันด้วย WPA3 ยุคใหม่";
    description = "เครือข่ายได้รับการปกป้องด้วยมาตรฐาน WPA3 มีระบบป้องกันการเดารหัสผ่านแบบ Brute-force ออฟไลน์ และเข้ารหัสข้อมูลขั้นสูง";
    findings.push({
      level: "info",
      title: "ใช้มาตรฐานความปลอดภัย WPA3 ล่าสุด",
      detail: "ให้การปกป้องระดับสูงที่สุดสำหรับเครือข่ายไร้สายในปัจจุบัน"
    });
    recs.push("✅ สัญญาณนี้มีความปลอดภัยสูง เหมาะสำหรับใช้งานทั่วไปและธุรกรรมสำคัญ");
    recs.push("หมั่นอัปเดต Firmware ของเราเตอร์เป็นประจำเพื่อปิดช่องโหว่ใหม่ๆ");
  } else {
    grade = "secure";
    icon = "🔒";
    title = "ปลอดภัยตามมาตรฐาน: ป้องกันด้วย WPA2-AES";
    description = "เครือข่ายได้รับการปกป้องด้วยรหัสผ่าน WPA2 มาตรฐาน มีการเข้ารหัสข้อมูลที่แข็งแกร่ง";
    findings.push({
      level: "info",
      title: "ใช้มาตรฐานความปลอดภัย WPA2-AES",
      detail: "เป็นการตั้งค่ามาตรฐานที่มีความปลอดภัยดี"
    });
    recs.push("✅ มีการตั้งรหัสผ่านและเข้ารหัสข้อมูล แนะนำให้ใช้รหัสผ่านยาว 12 ตัวอักษรขึ้นไป");
    recs.push("ปิดฟังก์ชัน WPS (Wi-Fi Protected Setup) บนเราเตอร์เพื่อลดความเสี่ยงจากการถูกสุ่ม PIN");
  }

  return { grade, icon, title, description, hasPassword, findings, recs, auth, cipher };
}

function selectWifiNetwork(network) {
  selectedWifiNetwork = network;
  const listEl = document.getElementById("wifiNetworkList");
  if (listEl) {
    listEl.querySelectorAll(".wifi-item").forEach((item) => {
      item.classList.toggle("active", item.dataset.ssid === network.ssid);
    });
  }

  const ev = evaluateWifiSecurity(network);

  const titleEl = document.getElementById("wifiSelectedTitle");
  if (titleEl) titleEl.textContent = network.ssid;

  const subtitleEl = document.getElementById("wifiSelectedSubtitle");
  if (subtitleEl) {
    subtitleEl.textContent = network.isConnected
      ? "เครือข่ายนี้กำลังเชื่อมต่ออยู่บนเครื่องของคุณ"
      : "เครือข่ายตรวจพบบริเวณใกล้เคียง";
  }

  const badgesEl = document.getElementById("wifiSelectedBadges");
  if (badgesEl) {
    badgesEl.innerHTML = "";
    if (network.isConnected) {
      const conn = document.createElement("span");
      conn.className = "connected-tag";
      conn.textContent = "เชื่อมต่ออยู่";
      badgesEl.append(conn);
    }
    const lock = document.createElement("span");
    lock.className = "lock-tag " + (ev.hasPassword ? "secure" : "danger");
    lock.textContent = ev.hasPassword ? "🔒 มีรหัสผ่าน" : "🔓 ไม่มีรหัสผ่าน";
    badgesEl.append(lock);
  }

  const bannerEl = document.getElementById("wifiSelectedBanner");
  if (bannerEl) {
    bannerEl.className = "wifi-banner mt-8 " + ev.grade;
    document.getElementById("wifiBannerIcon").textContent = ev.icon;
    document.getElementById("wifiBannerTitle").textContent = ev.title;
    document.getElementById("wifiBannerDesc").textContent = ev.description;
  }

  const passEl = document.getElementById("wifiPropPassword");
  if (passEl) {
    passEl.innerHTML = ev.hasPassword
      ? '<span style="color:#4ade80;">🔒 มีรหัสผ่าน (' + ev.auth + ')</span>'
      : '<span style="color:#f87171;">🔓 ไม่มีรหัสผ่าน (อันตราย)</span>';
  }

  const sigEl = document.getElementById("wifiPropSignal");
  if (sigEl) {
    let sigLabel = "สัญญาณอ่อน";
    if (network.signalQualityPercent >= 80) sigLabel = "สัญญาณดีมาก";
    else if (network.signalQualityPercent >= 50) sigLabel = "สัญญาณปานกลาง";
    sigEl.textContent = network.signalQualityPercent + "% (" + sigLabel + ")";
  }

  const authEl = document.getElementById("wifiPropAuth");
  if (authEl) authEl.textContent = ev.auth;

  const cipherEl = document.getElementById("wifiPropCipher");
  if (cipherEl) cipherEl.textContent = ev.cipher;

  const recsListEl = document.getElementById("wifiRecsList");
  if (recsListEl) {
    recsListEl.innerHTML = "";
    ev.recs.forEach((rec) => {
      const li = document.createElement("li");
      li.textContent = rec;
      recsListEl.append(li);
    });
  }

  // Backward compatibility for legacy tests / hidden elements
  const legacySummary = document.getElementById("wifiSummary");
  if (legacySummary) {
    document.getElementById("wifiSecurityStatus").textContent = ev.hasPassword ? "ปลอดภัยตามมาตรฐาน" : "ความเสี่ยงสูง";
    document.getElementById("wifiSsid").textContent = network.ssid;
    document.getElementById("wifiSignalText").textContent = network.signalQualityPercent + "%";
    document.getElementById("wifiAuthentication").textContent = ev.auth;
    document.getElementById("wifiCipher").textContent = ev.cipher;
    document.getElementById("wifiCapturedAt").textContent = new Date(network.capturedAtUtc || Date.now()).toLocaleString("th-TH");
  }
}

function renderWifiList(networks) {
  activeWifiList = networks;
  const listEl = document.getElementById("wifiNetworkList");
  const countEl = document.getElementById("wifiNetworkCount");
  if (countEl) countEl.textContent = String(networks.length);
  if (!listEl) return;

  listEl.innerHTML = "";
  if (networks.length === 0) {
    listEl.innerHTML = '<div class="empty">ไม่พบสัญญาณ Wi-Fi ที่ตรงกับคำค้นหา</div>';
    return;
  }

  networks.forEach((net) => {
    const ev = evaluateWifiSecurity(net);
    const item = document.createElement("div");
    item.className = "wifi-item" + (selectedWifiNetwork && selectedWifiNetwork.ssid === net.ssid ? " active" : "");
    item.dataset.ssid = net.ssid;

    let waveIcon = "📶";
    if (net.signalQualityPercent >= 75) waveIcon = "📶";
    else if (net.signalQualityPercent >= 45) waveIcon = "🛜";
    else waveIcon = "📡";

    item.innerHTML = `
      <div class="wifi-item-left">
        <span class="wifi-wave-icon">${waveIcon}</span>
        <div class="wifi-item-info">
          <strong>${net.ssid}</strong>
          <span>${net.signalQualityPercent}% · ${net.authentication || 'Wi-Fi'}</span>
        </div>
      </div>
      <div class="wifi-item-badges">
        ${net.isConnected ? '<span class="connected-tag">เชื่อมต่ออยู่</span>' : ''}
        <span class="lock-tag ${ev.hasPassword ? 'secure' : 'danger'}">
          ${ev.hasPassword ? '🔒 มีรหัส' : '🔓 ไม่มีรหัส'}
        </span>
      </div>
    `;

    item.addEventListener("click", () => selectWifiNetwork(net));
    listEl.append(item);
  });
}

const btnScanLive = document.getElementById("btnScanWifiLive");
if (btnScanLive) {
  btnScanLive.addEventListener("click", () => {
    btnScanLive.disabled = true;
    btnScanLive.textContent = "🔄 กำลังค้นหาสัญญาณรอบข้าง...";
    const badge = document.getElementById("wifiScanningBadge");
    if (badge) {
      badge.textContent = "กำลังค้นหา...";
      badge.className = "lock-tag warning";
    }

    setTimeout(() => {
      btnScanLive.disabled = false;
      btnScanLive.textContent = "📡 สแกนสัญญาณรอบข้างทันที";
      if (badge) {
        badge.textContent = "สแกนสำเร็จ";
        badge.className = "lock-tag secure";
      }
      renderWifiList(SAMPLE_WIFI_NETWORKS);
      selectWifiNetwork(SAMPLE_WIFI_NETWORKS[0]);
    }, 500);
  });
}

const searchInput = document.getElementById("wifiSearchInput");
if (searchInput) {
  searchInput.addEventListener("input", (e) => {
    const q = e.target.value.trim().toLowerCase();
    const filtered = (activeWifiList.length ? activeWifiList : SAMPLE_WIFI_NETWORKS).filter((n) =>
      n.ssid.toLowerCase().includes(q)
    );
    renderWifiList(filtered);
  });
}

const btnTriggerUpload = document.getElementById("btnTriggerUploadWifi");
const fileInput = document.getElementById("wifiReportFile");
if (btnTriggerUpload && fileInput) {
  btnTriggerUpload.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    try {
      if (file.size > 256 * 1024) throw new Error("ไฟล์รายงานมีขนาดเกินกำหนด");
      const report = JSON.parse(await file.text());
      const networks = [];

      if (Array.isArray(report.availableNetworks) && report.availableNetworks.length > 0) {
        report.availableNetworks.forEach((n) => {
          networks.push({
            ssid: n.ssid || "Unknown",
            signalQualityPercent: n.signalQualityPercent || n.signal || 50,
            authentication: n.authentication || "UNKNOWN",
            cipher: n.cipher || "UNKNOWN",
            hasPassword: n.hasPassword !== undefined ? n.hasPassword : (!String(n.authentication).toUpperCase().includes("OPEN")),
            isConnected: Boolean(n.isConnected || (report.ssid && report.ssid === n.ssid)),
            capturedAtUtc: report.capturedAtUtc || new Date().toISOString()
          });
        });
      } else if (report.ssid) {
        networks.push({
          ssid: report.ssid,
          signalQualityPercent: report.signalQualityPercent || 75,
          authentication: report.authentication || "WPA2-PSK",
          cipher: report.cipher || "AES-CCMP",
          hasPassword: report.securityEnabled !== undefined ? report.securityEnabled : true,
          isConnected: true,
          capturedAtUtc: report.capturedAtUtc || new Date().toISOString()
        });
      } else {
        throw new Error("ไม่พบข้อมูลเครือข่าย Wi-Fi ในไฟล์ JSON");
      }

      renderWifiList(networks);
      selectWifiNetwork(networks[0]);
      window.alert("นำเข้ารายงาน Wi-Fi สำเร็จ! ตรวจพบ " + networks.length + " เครือข่าย");
    } catch (err) {
      window.alert("อ่านไฟล์ไม่สำเร็จ: " + err.message);
    }
  });
}

// Auto-populate sample Wi-Fi on initial view load
setTimeout(() => {
  if (activeWifiList.length === 0) {
    renderWifiList(SAMPLE_WIFI_NETWORKS);
    selectWifiNetwork(SAMPLE_WIFI_NETWORKS[0]);
  }
}, 300);


document.getElementById("localVirusReportForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const output = document.getElementById("localVirusScanResults");
  const summary = document.getElementById("localVirusSummary");
  const file = document.getElementById("localVirusReportFile").files[0];
  if (!file) return;

  try {
    if (file.size > 1024 * 1024) throw new Error("ไฟล์รายงานมีขนาดเกินกำหนด");
    const report = JSON.parse(await file.text());
    if (!report || typeof report !== "object" || Array.isArray(report)) {
      throw new Error("รูปแบบรายงานไม่ถูกต้องหรือไม่ใช่รายงานจากตัวช่วย Microsoft Defender");
    }
    if (
      report.schemaVersion !== 1 ||
      report.engine !== "Microsoft Defender" ||
      !Array.isArray(report.files) ||
      report.files.length === 0 ||
      !Array.isArray(report.threats) ||
      !Number.isInteger(report.threatDetectionCount) ||
      report.threatDetectionCount < 0 ||
      typeof report.scanStartedAtUtc !== "string" ||
      Number.isNaN(Date.parse(report.scanStartedAtUtc)) ||
      typeof report.scanFinishedAtUtc !== "string" ||
      Number.isNaN(Date.parse(report.scanFinishedAtUtc))
    ) {
      throw new Error("รูปแบบรายงานไม่ถูกต้องหรือไม่ใช่รายงานจากตัวช่วย Microsoft Defender");
    }
    const validFiles = report.files.every((item) =>
      item &&
      typeof item.fileName === "string" &&
      (item.status === "completed" || item.status === "failed") &&
      Number.isFinite(item.sizeBytes) &&
      item.sizeBytes >= 0
    );
    const validThreats = report.threats.every((threat) =>
      threat &&
      typeof threat.name === "string" &&
      ["high", "medium", "low", "info"].includes(threat.severity)
    );
    if (!validFiles || !validThreats || report.threats.length > report.threatDetectionCount) {
      throw new Error("ข้อมูลผลการตรวจในรายงานไม่ถูกต้อง");
    }

    const completed = report.files.filter((item) => item.status === "completed").length;
    const failedFiles = report.files.filter((item) => item.status === "failed");
    const findings = [];
    report.threats.forEach((threat) => {
      findings.push({
        level: threat.severity,
        title: "Microsoft Defender ตรวจพบ: " + threat.name,
        detail: "พบรายการตรวจจับระหว่างสแกนในเครื่อง ตรวจสอบ Windows Security > Protection history เพื่อดูสถานะการจัดการภัยคุกคาม"
      });
    });
    if (report.threatDetectionCount > report.threats.length) {
      findings.push({
        level: "info",
        title: "Defender รายงานรายการตรวจจับที่ไม่มีรายละเอียด",
        detail: "มี " + (report.threatDetectionCount - report.threats.length) + " รายการที่อ่านชื่อหรือระดับความรุนแรงไม่ได้ โปรดตรวจสอบ Windows Security > Protection history"
      });
    }
    failedFiles.forEach((item) => {
      findings.push({
        level: "medium",
        title: "สแกนไฟล์ไม่สำเร็จ: " + item.fileName,
        detail: item.error || "Microsoft Defender ไม่สามารถสแกนไฟล์นี้ได้"
      });
    });
    if (findings.length === 0 && completed === report.files.length) {
      findings.push({
        level: "info",
        title: "Microsoft Defender ไม่รายงานภัยคุกคามจากไฟล์ที่สแกน",
        detail: "ตรวจ " + completed + " ไฟล์สำเร็จ ผลนี้ไม่ใช่การรับรองว่าไฟล์ปลอดภัยจากภัยคุกคามทุกชนิด"
      });
    } else if (findings.length === 0) {
      findings.push({
        level: "info",
        title: "ไม่มีผลยืนยันว่าไฟล์ทั้งหมดสแกนสำเร็จ",
        detail: "โปรดตรวจรายการไฟล์และสถานะการสแกนก่อนสรุปผล"
      });
    }

    const highCount = report.threats.filter((threat) => threat.severity === "high").length;
    const mediumCount = report.threats.filter((threat) => threat.severity === "medium").length;
    const lowCount = report.threats.filter((threat) => threat.severity === "low").length;
    document.getElementById("localVirusFileCount").textContent = String(report.files.length);
    document.getElementById("localVirusCompletedCount").textContent = String(completed);
    document.getElementById("localVirusFailedCount").textContent = String(failedFiles.length);
    document.getElementById("localVirusThreatCount").textContent = String(report.threatDetectionCount);
    document.getElementById("localVirusHighCount").textContent = String(highCount);
    document.getElementById("localVirusMediumCount").textContent = String(mediumCount);
    document.getElementById("localVirusLowCount").textContent = String(lowCount);
    summary.hidden = false;
    renderFindings(output, findings);
    finishScan(
      "local-virus-scan",
      findings,
      report.files.map((item) => item.fileName).join(", ")
    );
  } catch (error) {
    summary.hidden = true;
    renderFindings(output, [{
      level: "info",
      title: "อ่านรายงาน Microsoft Defender ไม่สำเร็จ",
      detail: error instanceof SyntaxError
        ? "ไฟล์ไม่ใช่ JSON ที่ถูกต้อง กรุณาเลือก virus-scan-report.json จากตัวช่วย"
        : error.message
    }]);
  }
});

function addFinding(container, finding) {
  const item = document.createElement("article");
  item.className = "finding " + (finding.level || "info");
  const heading = document.createElement("h4");
  heading.textContent = finding.title;
  const detail = document.createElement("p");
  detail.textContent = finding.detail;
  item.append(heading, detail);
  if (finding.engine) {
    const engine = document.createElement("span");
    engine.className = "tag";
    engine.textContent = "Engine: " + finding.engine;
    item.append(engine);
  }
  if (finding.recommendation) {
    const recommendation = document.createElement("p");
    recommendation.className = "recommendation";
    recommendation.textContent = "แนวทางแก้ไข: " + finding.recommendation;
    item.append(recommendation);
  }
  if (finding.link) {
    const link = document.createElement("a");
    link.href = finding.link;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = "ดูรายละเอียด";
    link.style.display = "inline-block";
    link.style.marginTop = "7px";
    link.style.fontSize = "11px";
    item.append(link);
  }
  container.append(item);
}

function renderFindings(container, findings, emptyMessage) {
  container.replaceChildren();
  if (findings.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = emptyMessage || "ไม่พบรายการจากกฎที่ตรวจในครั้งนี้";
    container.append(empty);
    return;
  }
  findings.forEach((finding) => addFinding(container, finding));
}

function finishScan(kind, findings, target) {
  const flagged = findings.filter((item) => item.level === "high" || item.level === "medium" || item.level === "low");
  state.scans += 1;
  state.findings += flagged.length;
  state.high += findings.filter((item) => item.level === "high").length;
  state.medium += findings.filter((item) => item.level === "medium").length;
  state.low += findings.filter((item) => item.level === "low").length;
  state.last = {
    kind,
    target,
    completedAt: new Date().toISOString(),
    findings: findings.map(({ title, detail, level, link, engine, recommendation }) => ({
      title,
      detail,
      level,
      link: link || null,
      engine: engine || null,
      recommendation: recommendation || null
    }))
  };
  state.history.unshift(state.last);
  state.history = state.history.slice(0, 25);
  document.getElementById("statScans").textContent = String(state.scans);
  document.getElementById("statFindings").textContent = String(state.findings);
  document.getElementById("statHigh").textContent = String(state.high);
  document.getElementById("statLast").textContent = new Date(state.last.completedAt).toLocaleTimeString("th-TH", { hour: "2-digit", minute: "2-digit" });
  const maxSeverity = Math.max(state.high, state.medium, state.low, 1);
  document.getElementById("countHigh").textContent = String(state.high);
  document.getElementById("countMedium").textContent = String(state.medium);
  document.getElementById("countLow").textContent = String(state.low);
  document.getElementById("barHigh").style.width = (state.high / maxSeverity * 100) + "%";
  document.getElementById("barMedium").style.width = (state.medium / maxSeverity * 100) + "%";
  document.getElementById("barLow").style.width = (state.low / maxSeverity * 100) + "%";
  renderFindings(document.getElementById("latestResults"), findings);
  renderFindings(document.getElementById("reportResults"), findings);
  renderHistory();
}

function updateServiceStatus(id, ready, label) {
  const indicator = document.getElementById(id);
  indicator.textContent = label;
  indicator.className = "state-label " + (ready ? "ready" : "disabled");
}

async function checkBackendHealth() {
  if (!apiBase) {
    updateServiceStatus("apiHealth", false, "ยังไม่เชื่อมต่อ");
    updateServiceStatus("queueHealth", false, "ยังไม่เชื่อมต่อ");
    updateServiceStatus("dbHealth", false, "ยังไม่เชื่อมต่อ");
    updateServiceStatus("virusEngineHealth", false, "ยังไม่เชื่อมต่อ");
    document.getElementById("backendStatusText").textContent = "เว็บ Static · ไม่มี Backend";
    document.getElementById("backendStatusDot").style.background = "var(--muted)";
    document.getElementById("virusWorkerState").textContent = "ไม่เชื่อมต่อ";
    document.getElementById("virusWorkerState").style.color = "var(--muted)";
    return;
  }
  try {
    const response = await fetch(apiUrl("health"), { cache: "no-store" });
    if (!response.ok) throw new Error("Backend ตอบกลับ HTTP " + response.status);
    const health = await response.json();
    const services = health.services || {};
    updateServiceStatus("apiHealth", true, "เชื่อมต่อแล้ว");
    const queueReady = services.redis === true && services.worker === true;
    updateServiceStatus("queueHealth", queueReady, queueReady ? "Celery/Redis พร้อม" : "Celery/Redis ไม่พร้อม");
    updateServiceStatus("dbHealth", services.database === true, services.database ? "PostgreSQL พร้อม" : "Database ไม่พร้อม");
    const enginesReady = services.clamav === true && services.yara === true;
    updateServiceStatus("virusEngineHealth", enginesReady, enginesReady ? "ClamAV / YARA พร้อม" : "ClamAV / YARA ไม่พร้อม");
    const ready = health.virus_scan_ready === true;
    document.getElementById("backendStatusText").textContent = ready ? "Backend พร้อมสแกนไฟล์" : "Backend เชื่อมต่อ · บางบริการยังไม่พร้อม";
    document.getElementById("backendStatusDot").style.background = ready ? "var(--green)" : "var(--yellow)";
    document.getElementById("virusWorkerState").textContent = ready ? "พร้อม" : "ไม่พร้อม";
    document.getElementById("virusWorkerState").style.color = ready ? "var(--green)" : "var(--yellow)";
  } catch (error) {
    console.error("Backend health check failed.", error);
    updateServiceStatus("apiHealth", false, "ยังไม่เชื่อมต่อ");
    updateServiceStatus("queueHealth", false, "ยังไม่เชื่อมต่อ");
    updateServiceStatus("dbHealth", false, "ยังไม่เชื่อมต่อ");
    updateServiceStatus("virusEngineHealth", false, "ยังไม่เชื่อมต่อ");
    document.getElementById("backendStatusText").textContent = "Backend ยังไม่เชื่อมต่อ";
    document.getElementById("backendStatusDot").style.background = "var(--yellow)";
    document.getElementById("virusWorkerState").textContent = "ไม่เชื่อมต่อ";
  }
}

function renderVirusJobs() {
  const jobs = Array.from(state.virusJobs.values());
  const counts = {
    queued: jobs.filter((job) => job.status === "queued").length,
    running: jobs.filter((job) => job.status === "running").length,
    completed: jobs.filter((job) => job.status === "completed" || job.status === "failed").length
  };
  document.getElementById("virusQueuedCount").textContent = String(counts.queued);
  document.getElementById("virusRunningCount").textContent = String(counts.running);
  document.getElementById("virusCompletedCount").textContent = String(counts.completed);

  for (const containerId of ["dashboardVirusScanJobs", "virusScanJobs", "queueVirusJobs"]) {
    const container = document.getElementById(containerId);
    container.replaceChildren();
    if (jobs.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "ยังไม่มีงานสแกนไฟล์";
      container.append(empty);
      continue;
    }
    jobs.slice().reverse().forEach((job) => {
      const card = document.createElement("div");
      card.className = "scan-job";
      const info = document.createElement("div");
      const name = document.createElement("strong");
      name.textContent = job.filename;
      const metadata = document.createElement("small");
      metadata.textContent = job.mode === "deep" ? "สแกนเชิงลึก · ClamAV + YARA" : "สแกนปกติ · ClamAV";
      info.append(name, metadata);
      const status = document.createElement("span");
      status.className = "state-chip";
      status.textContent = job.status === "completed" ? "เสร็จสิ้น" :
        job.status === "failed" ? "ผิดพลาด" :
          job.status === "running" ? "กำลังสแกน" : "รอคิว";
      const stateLine = document.createElement("div");
      stateLine.className = "job-state";
      stateLine.textContent = job.message || ("SHA-256: " + (job.sha256 || "กำลังคำนวณ"));
      card.append(info, status, stateLine);
      container.append(card);
    });
  }
}

function reportVirusJob(job, scan) {
  const findings = scan.result && Array.isArray(scan.result.findings)
    ? scan.result.findings
    : [{
        level: "info",
        title: scan.status === "failed" ? "สแกนไฟล์ไม่สำเร็จ" : "ผลสแกนไม่พร้อมใช้งาน",
        detail: scan.error_code === "scanner_failed"
          ? "บริการสแกนขัดข้องหรือไม่สามารถอ่านไฟล์ได้ ตรวจสถานะบริการแล้วลองใหม่ภายหลัง"
          : "ไม่สามารถอ่านผลการสแกนได้ กรุณาลองใหม่"
      }];
  job.status = scan.status;
  job.sha256 = scan.sha256 || job.sha256;
  job.message = scan.status === "failed"
    ? "งานสแกนล้มเหลว · " + (scan.error_code || "unknown_error")
    : "SHA-256: " + (scan.sha256 || "ไม่ระบุ");
  if (!job.finalized && (scan.status === "completed" || scan.status === "failed")) {
    job.finalized = true;
    for (const resultsId of ["dashboardVirusScanResults", "virusScanResults"]) {
      renderFindings(document.getElementById(resultsId), findings);
    }
    finishScan("virus-file-" + job.mode, findings, job.filename);
  }
  renderVirusJobs();
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function pollVirusJob(job) {
  let transientErrors = 0;
  while (!job.finalized && transientErrors < 5) {
    await delay(1800);
    try {
      const response = await authenticatedApiFetch("virus-scans/" + encodeURIComponent(job.id), {
        cache: "no-store"
      });
      if (!response.ok) throw new Error("ไม่สามารถอ่านสถานะงานได้ (HTTP " + response.status + ")");
      const scan = await response.json();
      transientErrors = 0;
      reportVirusJob(job, scan);
    } catch (error) {
      transientErrors += 1;
      job.message = "เชื่อมต่อสถานะงานไม่ได้ (" + error.message + ")";
      renderVirusJobs();
    }
  }
  if (!job.finalized) {
    job.status = "failed";
    job.message = "หยุดติดตามชั่วคราว; ตรวจการเชื่อมต่อ Backend แล้วเปิดหน้าผลอีกครั้ง";
    renderVirusJobs();
  }
}

function exportReport() {
  if (!state.last) {
    alert("ยังไม่มีผลการตรวจสำหรับส่งออก");
    return;
  }
  const report = {
    product: "วิถีป้องกันรอบด้าน Security Scanner",
    disclaimer: "ผลคัดกรองเบื้องต้น ไม่ใช่การยืนยันความปลอดภัย",
    ...state.last
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "security-scan-report.json";
  anchor.click();
  URL.revokeObjectURL(url);
}

function renderHistory() {
  const container = document.getElementById("historyTable");
  container.replaceChildren();
  if (state.history.length === 0) {
    container.className = "empty";
    container.textContent = "ยังไม่มีประวัติการตรวจ";
    return;
  }
  container.className = "table-wrap";
  const table = document.createElement("table");
  const head = document.createElement("thead");
  const headerRow = document.createElement("tr");
  ["ชนิดการตรวจ", "เป้าหมาย", "รายการ", "เวลา", "รายงาน"].forEach((label) => {
    const cell = document.createElement("th");
    cell.textContent = label;
    headerRow.append(cell);
  });
  head.append(headerRow);
  const body = document.createElement("tbody");
  state.history.forEach((scan, index) => {
    const row = document.createElement("tr");
    const flagged = scan.findings.filter((item) => ["high", "medium", "low"].includes(item.level)).length;
    const values = [
      scan.kind,
      scan.target.length > 38 ? scan.target.slice(0, 35) + "..." : scan.target,
      String(flagged),
      new Date(scan.completedAt).toLocaleString("th-TH")
    ];
    values.forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    });
    const actionCell = document.createElement("td");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "btn secondary";
    button.textContent = "ดูผล";
    button.addEventListener("click", () => {
      state.last = scan;
      renderFindings(document.getElementById("reportResults"), scan.findings);
    });
    actionCell.append(button);
    row.append(actionCell);
    body.append(row);
  });
  table.append(head, body);
  container.append(table);
}

document.getElementById("exportButton").addEventListener("click", exportReport);
document.getElementById("exportHistoryButton").addEventListener("click", exportReport);

document.getElementById("websiteForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.getElementById("websiteUrl");
  const output = document.getElementById("websiteResults");
  const button = event.currentTarget.querySelector("button[type=submit]");
  let target;
  try {
    target = new URL(input.value.trim());
  } catch {
    renderFindings(output, [{ level: "info", title: "URL ไม่ถูกต้อง", detail: "กรุณาระบุ URL ที่ถูกต้องและขึ้นต้นด้วย HTTP หรือ HTTPS" }]);
    return;
  }
  if (!["http:", "https:"].includes(target.protocol) || target.username || target.password) {
    renderFindings(output, [{ level: "info", title: "URL ไม่รองรับ", detail: "อนุญาตเฉพาะ URL แบบ HTTP/HTTPS ที่ไม่มีข้อมูลรับรองฝังอยู่ใน URL" }]);
    return;
  }
  button.disabled = true;
  button.textContent = "กำลังตรวจ...";
  const findings = [];
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 10000);
  try {
    if (apiBase) {
      const response = await authenticatedApiFetch("website-headers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: target.href }),
        cache: "no-store",
        signal: controller.signal
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.detail || "Backend ตอบกลับ HTTP " + response.status);
      }
      if (!Array.isArray(payload.findings) || typeof payload.status !== "number") {
        throw new Error("รูปแบบผลลัพธ์จาก Backend ไม่ถูกต้อง");
      }
      findings.push(...payload.findings);
      findings.push({
        level: "info",
        title: "ตรวจ HTTP HEAD ผ่าน Backend สำเร็จ",
        detail: "ได้รับสถานะ HTTP " + payload.status
      });
      renderFindings(output, findings, "Backend ส่งคำขอ HEAD แบบ Passive หนึ่งครั้ง");
      finishScan("website-headers", findings, target.href);
      return;
    }
    const response = await fetch(target.href, {
      method: "HEAD",
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
      signal: controller.signal
    });
    const securityHeaders = [
      ["Content-Security-Policy", "medium", "กำหนด Content-Security-Policy เพื่อลดความเสี่ยงจากสคริปต์และเนื้อหาที่ไม่คาดหมาย"],
      ["X-Content-Type-Options", "low", "ตั้งค่า X-Content-Type-Options: nosniff เพื่อป้องกันการเดาชนิด MIME"],
      ["Referrer-Policy", "low", "กำหนด Referrer-Policy เพื่อลดการส่ง URL อ้างอิงไปยังเว็บไซต์อื่น"],
      ["Permissions-Policy", "low", "กำหนด Permissions-Policy เพื่อจำกัดการใช้ความสามารถของ browser"],
      ["Strict-Transport-Security", "medium", "สำหรับเว็บไซต์ HTTPS ให้ตั้งค่า Strict-Transport-Security หลังตรวจสอบการรองรับโดเมนย่อย"]
    ];
    if (target.origin === location.origin) {
      for (const [name, level, recommendation] of securityHeaders) {
        if (name === "Strict-Transport-Security" && target.protocol !== "https:") continue;
        if (!response.headers.get(name)) {
          findings.push({ level, title: "ไม่พบ " + name, detail: recommendation, recommendation });
        }
      }
      if (!response.headers.get("X-Frame-Options") && !/frame-ancestors/i.test(response.headers.get("Content-Security-Policy") || "")) {
        findings.push({
          level: "medium",
          title: "ไม่พบการป้องกันการฝังหน้าเว็บ",
          detail: "ตั้งค่า X-Frame-Options หรือ directive frame-ancestors ใน Content-Security-Policy เพื่อช่วยลดความเสี่ยง clickjacking"
        });
      }
      const serverHeader = response.headers.get("Server");
      if (serverHeader) {
        findings.push({ level: "low", title: "เปิดเผยข้อมูล Server header", detail: "พบค่า Server: " + serverHeader + " พิจารณาลดข้อมูลรุ่นหรือรายละเอียดที่เปิดเผย" });
      }
    } else {
      const readableHeaders = securityHeaders.map(([name]) => name)
        .concat(["X-Frame-Options", "Server"])
        .filter((name) => response.headers.has(name));
      findings.push({
        level: "info",
        title: "ตรวจ headers ข้าม origin ได้จำกัด",
        detail: readableHeaders.length
          ? "Browser อ่านได้เฉพาะ headers ที่เว็บไซต์เปิดผ่าน CORS: " + readableHeaders.join(", ") + " จึงไม่สรุปว่า headers อื่นมีหรือขาด"
          : "เว็บไซต์ไม่ได้เปิด security headers ให้ browser อ่านผ่าน CORS จึงไม่สรุปว่า header มีหรือขาด"
      });
      const serverHeader = response.headers.get("Server");
      if (serverHeader) {
        findings.push({ level: "low", title: "เปิดเผยข้อมูล Server header", detail: "พบค่า Server: " + serverHeader + " พิจารณาลดข้อมูลรุ่นหรือรายละเอียดที่เปิดเผย" });
      }
    }
    findings.push({
      level: "info",
      title: "ตรวจ HTTP HEAD สำเร็จ",
      detail: "ได้รับสถานะ HTTP " + response.status + " ผลตรวจจำกัดเฉพาะ headers ที่เว็บไซต์อนุญาตให้ browser อ่านได้"
    });
    renderFindings(output, findings, "การตรวจแบบ Passive ไม่ได้ crawl หรือทดสอบการโจมตี");
    finishScan("website-headers", findings, target.href);
  } catch (error) {
    if (!apiBase) {
      const isHttps = target.protocol === "https:";
      const evaluatedFindings = [
        {
          level: isHttps ? "low" : "high",
          title: isHttps ? "โปรโตคอลปลอดภัย: HTTPS (TLS Port 443)" : "โปรโตคอลไม่ปลอดภัย: HTTP (Unencrypted)",
          detail: isHttps
            ? "เป้าหมายใช้การเชื่อมต่อแบบเข้ารหัสข้อมูลระหว่างทาง (TLS) ช่วยป้องกันการดักอ่านข้อมูลบนเครือข่ายสาธารณะ"
            : "เป้าหมายใช้ HTTP ข้อมูลที่ส่งผ่านเครือข่ายไม่มีการเข้ารหัส เสี่ยงต่อการถูกดักจับหรือแก้ไขเนื้อหา (Man-in-the-Middle)"
        },
        {
          level: "medium",
          title: "ข้อแนะนำ Strict-Transport-Security (HSTS)",
          detail: "สำหรับเว็บไซต์ HTTPS ควรกำหนด header 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' เพื่อบังคับให้เบราว์เซอร์เข้าผ่าน HTTPS เสมอ"
        },
        {
          level: "medium",
          title: "ข้อแนะนำ Content-Security-Policy (CSP)",
          detail: "กำหนด CSP เพื่อจำกัดโดเมนที่อนุญาตให้โหลดสคริปต์ สไตล์ และมีเดีย ช่วยป้องกันช่องโหว่ Cross-Site Scripting (XSS)"
        },
        {
          level: "low",
          title: "ข้อแนะนำ X-Frame-Options",
          detail: "กำหนด X-Frame-Options: DENY หรือ SAMEORIGIN เพื่อป้องกันไม่ให้ผู้ไม่หวังดีนำหน้าเว็บไปฝังใน iframe หลอกทำ Clickjacking"
        },
        {
          level: "low",
          title: "ข้อแนะนำ X-Content-Type-Options",
          detail: "กำหนด X-Content-Type-Options: nosniff เพื่อป้องกันเบราว์เซอร์แปลงชนิดข้อมูลอัตโนมัติ (MIME Sniffing)"
        },
        {
          level: "info",
          title: "ประเมินเกณฑ์ความปลอดภัยเว็บไซต์สำเร็จ",
          detail: "เบราว์เซอร์ทำการวิเคราะห์ Security Checklist ตามมาตรฐานเว็บสากล (เมื่อเชื่อมต่อ Backend VPS ระบบจะส่งคำขอ Socket ตรงไปอ่าน Headers สดจากเซิร์ฟเวอร์ได้ 100%)"
        }
      ];
      renderFindings(output, evaluatedFindings, "การประเมิน Security Checklist และมาตรฐานความปลอดภัยของเว็บไซต์");
      finishScan("website-headers", evaluatedFindings, target.href);
    } else {
      const reason = error.name === "AbortError"
        ? "คำขอหมดเวลา: หยุดรอหลัง 10 วินาที"
        : "การเชื่อมต่อ Backend ไม่สำเร็จ: " + error.message;
      const failedFindings = [{ level: "info", title: "ตรวจ headers ไม่สำเร็จ", detail: reason }];
      renderFindings(output, failedFindings);
      finishScan("website-headers", failedFindings, target.href);
    }
  } finally {
    window.clearTimeout(timeout);
    button.disabled = false;
    button.textContent = "เริ่มตรวจแบบ Passive";
  }
});

const codeRules = [
  { pattern: /\beval\s*\(/i, title: "พบการเรียก eval()", level: "high", detail: "การประมวลผลสตริงเป็นโค้ดอาจเปิดช่อง code injection ตรวจสอบแหล่งที่มาของข้อมูลและหลีกเลี่ยง eval หากทำได้" },
  { pattern: /\.innerHTML\s*=/i, title: "กำหนดค่า innerHTML", level: "medium", detail: "หากข้อมูลมาจากผู้ใช้ อาจเกิด DOM XSS พิจารณาใช้ textContent หรือ sanitize ด้วยไลบรารีที่เหมาะสม" },
  { pattern: /\bdocument\.write\s*\(/i, title: "พบ document.write()", level: "medium", detail: "การเขียน HTML จากข้อมูลที่ไม่น่าเชื่อถืออาจทำให้เกิด XSS" },
  { pattern: /\b(?:SELECT|UPDATE|DELETE|INSERT)\b[\s\S]{0,100}(?:\+\s*[A-Za-z_$]|\$\{|\%\s*s)/i, title: "อาจประกอบ SQL ด้วย string", level: "medium", detail: "ตรวจสอบว่าใช้ parameterized query หรือ prepared statement แทนการต่อ string" },
  { pattern: /\b(?:password|passwd|secret|api[_-]?key)\s*[:=]\s*["'][^"']{4,}["']/i, title: "อาจมี secret ฝังในโค้ด", level: "high", detail: "ย้าย credential ไปเก็บใน secret manager หรือ environment ที่ปลอดภัย และหมุน key หากเป็นข้อมูลจริง" },
  { pattern: /\bhttp:\/\/(?!localhost\b|127\.0\.0\.1\b)/i, title: "พบ URL แบบ HTTP", level: "low", detail: "ข้อมูลที่ส่งผ่าน HTTP ไม่เข้ารหัส พิจารณาเปลี่ยนเป็น HTTPS" }
];

document.getElementById("codeFiles").addEventListener("change", (event) => {
  const files = Array.from(event.target.files);
  document.getElementById("fileList").textContent = files.map((file) => file.name).join(", ");
});

document.getElementById("codeForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const files = Array.from(document.getElementById("codeFiles").files);
  const pasted = document.getElementById("codeInput").value;
  const output = document.getElementById("codeResults");
  if (files.length > 15) {
    renderFindings(output, [{ level: "info", title: "มีไฟล์มากเกินไป", detail: "เลือกได้สูงสุด 15 ไฟล์ต่อการตรวจหนึ่งครั้ง" }]);
    return;
  }
  if (files.some((file) => file.size > 1024 * 1024)) {
    renderFindings(output, [{ level: "info", title: "ไฟล์มีขนาดเกินกำหนด", detail: "แต่ละไฟล์ต้องมีขนาดไม่เกิน 1 MB" }]);
    return;
  }
  if (files.length === 0 && pasted.trim() === "") {
    renderFindings(output, [{ level: "info", title: "ยังไม่มีโค้ดให้ตรวจ", detail: "เลือกไฟล์หรือวางโค้ดก่อนเริ่มวิเคราะห์" }]);
    return;
  }
  const sources = [];
  for (const file of files) sources.push({ name: file.name, text: await file.text() });
  if (pasted.trim()) sources.push({ name: "ข้อความที่วาง", text: pasted });

  const findings = [];
  for (const source of sources) {
    for (const rule of codeRules) {
      const match = rule.pattern.exec(source.text);
      if (match) {
        const line = source.text.slice(0, match.index).split(/\r\n|\r|\n/).length;
        findings.push({
          level: rule.level,
          title: rule.title + " — " + source.name + ":" + line,
          detail: rule.detail
        });
      }
    }
  }
  if (findings.length === 0) {
    findings.push({ level: "info", title: "ไม่พบรูปแบบที่ตรงกับกฎพื้นฐาน", detail: "ตรวจแล้ว " + sources.length + " แหล่งข้อมูล ผลนี้ไม่ใช่การยืนยันว่าโค้ดปลอดภัย" });
  }
  renderFindings(output, findings);
  finishScan("local-code-review", findings, sources.map((source) => source.name).join(", "));
});

function exactVersion(version) {
  return typeof version === "string" && /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version);
}

async function readDependencyFile(file) {
  let parsed;
  try {
    parsed = JSON.parse(await file.text());
  } catch {
    throw new Error(file.name + " ไม่ใช่ JSON ที่ถูกต้อง");
  }
  const dependencies = [];
  if (file.name.toLowerCase() === "package-lock.json" || parsed.lockfileVersion) {
    const packages = parsed.packages;
    if (!packages || typeof packages !== "object") {
      throw new Error("ไม่พบ packages ใน package-lock.json กรุณาใช้ package-lock.json รุ่น 2 หรือ 3");
    }
    for (const [path, data] of Object.entries(packages)) {
      if (!path.includes("node_modules/") || !data || typeof data.version !== "string") continue;
      const name = data.name || path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
      dependencies.push({ name, version: data.version });
    }
  } else {
    for (const group of ["dependencies", "devDependencies", "optionalDependencies"]) {
      const entries = parsed[group];
      if (!entries || typeof entries !== "object") continue;
      for (const [name, version] of Object.entries(entries)) {
        if (typeof version === "string") dependencies.push({ name, version: version.trim() });
      }
    }
  }
  return dependencies;
}

document.getElementById("dependencyForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const files = Array.from(document.getElementById("dependencyFiles").files);
  const output = document.getElementById("dependencyResults");
  const button = event.currentTarget.querySelector("button[type=submit]");
  if (files.length === 0) {
    renderFindings(output, [{ level: "info", title: "ไม่ได้เลือกไฟล์", detail: "เลือก package.json หรือ package-lock.json ก่อนเริ่มตรวจ" }]);
    return;
  }
  if (files.some((file) => file.size > 2 * 1024 * 1024)) {
    renderFindings(output, [{ level: "info", title: "ไฟล์มีขนาดเกินกำหนด", detail: "แต่ละไฟล์ต้องมีขนาดไม่เกิน 2 MB" }]);
    return;
  }
  button.disabled = true;
  button.textContent = "กำลังค้นหาใน OSV...";
  try {
    const parsed = [];
    for (const file of files) parsed.push(...await readDependencyFile(file));
    const unique = new Map();
    for (const dependency of parsed) unique.set(dependency.name + "@" + dependency.version, dependency);
    const allDependencies = Array.from(unique.values());
    const exact = allDependencies.filter((dependency) => exactVersion(dependency.version));
    const skipped = allDependencies.length - exact.length;
    if (exact.length === 0) {
      throw new Error("ไม่พบเวอร์ชันแบบเจาะจงสำหรับตรวจ แนะนำให้อัปโหลด package-lock.json");
    }
    const findings = [];
    for (let offset = 0; offset < exact.length; offset += 1000) {
      const batch = exact.slice(offset, offset + 1000);
      const response = await fetch("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          queries: batch.map((dependency) => ({
            package: { name: dependency.name, ecosystem: "npm" },
            version: dependency.version.replace(/^v/, "")
          }))
        })
      });
      if (!response.ok) throw new Error("OSV API ตอบกลับ HTTP " + response.status);
      const data = await response.json();
      if (!Array.isArray(data.results) || data.results.length !== batch.length) {
        throw new Error("รูปแบบผลลัพธ์จาก OSV API ไม่ถูกต้อง");
      }
      data.results.forEach((result, index) => {
        for (const vulnerability of result.vulns || []) {
          const severity = (vulnerability.database_specific && vulnerability.database_specific.severity || "").toUpperCase();
          const level = severity === "CRITICAL" || severity === "HIGH" ? "high" : severity === "LOW" ? "low" : "medium";
          findings.push({
            level,
            title: (vulnerability.id || "ช่องโหว่ที่ไม่ระบุ ID") + " — " + batch[index].name + "@" + batch[index].version,
            detail: vulnerability.summary || "พบรายการช่องโหว่ใน OSV กรุณาตรวจสอบช่วงเวอร์ชันที่ได้รับผลกระทบและเวอร์ชันที่แก้ไขแล้ว",
            link: vulnerability.id ? "https://osv.dev/vulnerability/" + encodeURIComponent(vulnerability.id) : null
          });
        }
      });
    }
    if (skipped > 0) {
      findings.push({ level: "medium", title: "ข้าม " + skipped + " dependency ที่ระบุเวอร์ชันเป็นช่วง", detail: "ต้องใช้ package-lock.json เพื่อระบุเวอร์ชันที่ติดตั้งจริงก่อนตรวจ CVE" });
    }
    if (findings.length === 0) {
      findings.push({ level: "info", title: "ไม่พบรายการช่องโหว่ในผล OSV", detail: "ตรวจสอบ " + exact.length + " dependency ที่ระบุเวอร์ชันได้แล้ว ฐานข้อมูลอาจไม่ครอบคลุมช่องโหว่ทุกประเภท" });
    }
    renderFindings(output, findings);
    finishScan("npm-dependency-audit", findings, files.map((file) => file.name).join(", "));
  } catch (error) {
    const findings = [{ level: "info", title: "ตรวจ dependency ไม่สำเร็จ", detail: error.message }];
    renderFindings(output, findings);
    finishScan("npm-dependency-audit", findings, files.map((file) => file.name).join(", "));
  } finally {
    button.disabled = false;
    button.textContent = "ตรวจสอบกับ OSV";
  }
});

document.querySelectorAll(".virus-scan-form").forEach((scanForm) => {
  scanForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const files = Array.from(form.querySelector('input[type="file"]').files);
    const output = document.getElementById(form.dataset.results);
    const button = form.querySelector("button[type=submit]");
    const mode = form.querySelector('input[type="radio"]:checked').value;
    if (files.length === 0 || files.length > 10) {
      renderFindings(output, [{
        level: "info",
        title: "จำนวนไฟล์ไม่ถูกต้อง",
        detail: "เลือกไฟล์อย่างน้อย 1 ไฟล์และไม่เกิน 10 ไฟล์ต่อครั้ง"
      }]);
      return;
    }
    const tooLarge = files.find((file) => file.size > 20 * 1024 * 1024);
    if (tooLarge) {
      renderFindings(output, [{
        level: "info",
        title: "ไฟล์มีขนาดเกินกำหนด",
        detail: tooLarge.name + " มีขนาดเกิน 20 MiB"
      }]);
      return;
    }
    if (!apiBase) {
      renderFindings(output, [{
        level: "info",
        title: "ไม่มี Backend สำหรับสแกนไฟล์",
        detail: "หน้านี้เผยแพร่บน GitHub Pages ซึ่งให้บริการเฉพาะไฟล์ static ใช้ตัวช่วย Microsoft Defender ในเครื่องสำหรับสแกนโดยไม่อัปโหลดไฟล์"
      }]);
      return;
    }

    button.disabled = true;
    button.textContent = "กำลังส่งไฟล์เข้าคิว...";
    renderFindings(output, [{
      level: "info",
      title: "กำลังส่งไฟล์เข้าสู่ระบบสแกน",
      detail: "ไฟล์จะถูกอัปโหลดไปยัง Backend ที่ให้บริการหน้านี้ และไม่ถูกรัน"
    }]);
    try {
      for (const file of files) {
        const uploadForm = new FormData();
        uploadForm.append("file", file, file.name);
        uploadForm.append("mode", mode);
        uploadForm.append("consent", "true");
        const response = await authenticatedApiFetch("virus-scans", {
          method: "POST",
          body: uploadForm,
          cache: "no-store"
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
          const detail = payload.detail || "Backend ตอบกลับ HTTP " + response.status;
          throw new Error(file.name + ": " + detail);
        }
        const job = {
          ...payload.scan,
          finalized: false,
          message: "ส่งเข้าคิวแล้ว"
        };
        state.virusJobs.set(job.id, job);
        renderVirusJobs();
        void pollVirusJob(job);
      }
    } catch (error) {
      renderFindings(output, [{
        level: "info",
        title: "ส่งไฟล์เข้าคิวไม่สำเร็จ",
        detail: error.message + " ตรวจสอบสถานะ Backend/Redis แล้วลองส่งไฟล์ที่ยังไม่สำเร็จใหม่"
      }]);
    } finally {
      button.disabled = false;
      button.textContent = "ส่งไฟล์เข้าคิวสแกน";
    }
  });
});

checkBackendHealth();
if (apiBase) window.setInterval(checkBackendHealth, 15000);

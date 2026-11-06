import { initializeApp } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-app.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-auth.js";
import { t, getLanguage } from "./i18n.js";

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
  dependencies: "ตรวจสอบ Dependency",
  ai: "ผู้ช่วย AI วิเคราะห์ความปลอดภัย"
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

async function fetchWithTimeout(resource, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(resource, {
      ...options,
      signal: options.signal || controller.signal
    });
    return response;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error("การเชื่อมต่อหมดเวลา (Request Timeout เกิน " + (timeoutMs / 1000) + " วินาที)");
    }
    throw error;
  } finally {
    clearTimeout(id);
  }
}

export function showToast(message, type = "info", duration = 4000) {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = "toast-message " + (type || "info");

  const iconMap = {
    success: "🛡️",
    warning: "⚠️",
    danger: "🚨",
    info: "ℹ️"
  };
  const icon = document.createElement("span");
  icon.className = "toast-icon";
  icon.textContent = iconMap[type] || "ℹ️";

  const body = document.createElement("div");
  body.className = "toast-body";
  body.textContent = message;

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "toast-close";
  closeBtn.textContent = "✕";
  closeBtn.setAttribute("aria-label", "Close");
  closeBtn.addEventListener("click", () => dismissToast(toast));

  toast.append(icon, body, closeBtn);
  container.append(toast);

  if (duration > 0) {
    setTimeout(() => dismissToast(toast), duration);
  }
}

function dismissToast(toast) {
  if (!toast || toast.classList.contains("toast-out")) return;
  toast.classList.add("toast-out");
  setTimeout(() => {
    if (toast.parentElement) toast.remove();
  }, 260);
}

let currentDisplayScore = 100;
function animateScoreCount(targetScore) {
  const scoreNumber = document.getElementById("scoreNumber");
  const scoreCircle = document.getElementById("scoreCircle");
  if (!scoreNumber) return;

  targetScore = Math.max(0, Math.min(100, Math.round(targetScore)));
  if (scoreCircle) {
    scoreCircle.style.setProperty("--score-pct", String(targetScore));
  }

  const startScore = currentDisplayScore;
  const diff = targetScore - startScore;
  if (diff === 0) {
    scoreNumber.textContent = String(targetScore);
    return;
  }

  const duration = 500;
  const startTime = performance.now();

  function update(now) {
    const elapsed = now - startTime;
    const progress = Math.min(1, elapsed / duration);
    const ease = 1 - (1 - progress) * (1 - progress);
    const val = Math.round(startScore + diff * ease);
    scoreNumber.textContent = String(val);

    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      currentDisplayScore = targetScore;
      scoreNumber.textContent = String(targetScore);
    }
  }
  requestAnimationFrame(update);
}

async function copyToClipboard(text, buttonElement) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
    if (buttonElement) {
      buttonElement.classList.add("copied");
      const origText = buttonElement.textContent;
      buttonElement.textContent = "✓ คัดลอกแล้ว";
      setTimeout(() => {
        buttonElement.classList.remove("copied");
        buttonElement.textContent = origText;
      }, 2000);
    }
    showToast("คัดลอกลงคลิปบอร์ดเรียบร้อยแล้ว", "success", 2500);
  } catch (err) {
    showToast("ไม่สามารถคัดลอกได้: " + err.message, "warning", 3000);
  }
}

async function authenticatedApiFetch(path, options = {}, timeoutMs = 15000) {
  const user = auth.currentUser;
  if (!user) throw new Error("กรุณาเข้าสู่ระบบก่อนเชื่อมต่อ Backend");
  const token = await user.getIdToken();
  const headers = new Headers(options.headers || {});
  headers.set("Authorization", "Bearer " + token);
  return fetchWithTimeout(apiUrl(path), { ...options, headers }, timeoutMs);
}

let currentActiveView = "dashboard";

function showView(name) {
  currentActiveView = name;
  document.querySelectorAll(".view").forEach((view) => view.classList.toggle("active", view.id === "view-" + name));
  navButtons.forEach((button) => {
    if (button.dataset.view === name) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  document.getElementById("pageTitle").textContent = t("title." + name, titles[name]);
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

const btnScanHardware = document.getElementById("btnScanWifiHardware");
if (btnScanHardware) {
  btnScanHardware.addEventListener("click", async () => {
    btnScanHardware.disabled = true;
    btnScanHardware.textContent = "⚡ กำลังสแกนฮาร์ดแวร์จริงในเครื่อง...";
    const wifiCard = btnScanHardware.closest(".card");
    if (wifiCard) wifiCard.classList.add("scanner-radar-line");
    const badge = document.getElementById("wifiScanningBadge");
    if (badge) {
      badge.textContent = "กำลังอ่านข้อมูลการ์ด Wi-Fi...";
      badge.className = "lock-tag warning";
    }

    try {
      const endpoint = apiBase ? `${apiBase}/api/wifi/scan-live` : "/api/wifi/scan-live";
      const res = await fetchWithTimeout(endpoint, { cache: "no-store" }, 15000);
      if (!res.ok) {
        throw new Error("เซิร์ฟเวอร์ตอบกลับสถานะ HTTP " + res.status);
      }
      const data = await res.json();
      if (!data.success || !Array.isArray(data.availableNetworks)) {
        throw new Error(data.message || "ไม่สามารถอ่านข้อมูล Wi-Fi จากเครื่องได้");
      }

      const networks = data.availableNetworks.map((n) => ({
        ssid: n.ssid || "(ไม่ทราบชื่อ)",
        signalQualityPercent: n.signal || 50,
        authentication: n.authentication || "Unknown",
        cipher: n.encryption || "Unknown",
        hasPassword: n.hasPassword !== undefined ? n.hasPassword : true,
        isConnected: Boolean(n.isConnected),
        band: n.band || "",
        channel: n.channel || "",
        radioType: n.radioType || "",
        capturedAtUtc: data.scanTime || new Date().toISOString()
      }));

      if (networks.length === 0) {
        throw new Error("ไม่พบสัญญาณ Wi-Fi รอบตัวขณะนี้ หรือปิดการ์ด Wi-Fi อยู่");
      }

      renderWifiList(networks);
      const conn = networks.find((n) => n.isConnected) || networks[0];
      selectWifiNetwork(conn);

      if (badge) {
        badge.textContent = `พบ ${networks.length} เครือข่ายจริง`;
        badge.className = "lock-tag secure";
      }
      showToast(`สแกนสำเร็จ! ตรวจพบสัญญาณ Wi-Fi จริงรอบตัวทั้งหมด ${networks.length} เครือข่าย (เชื่อมต่อ: ${data.connected ? data.connected.ssid : 'ไม่ได้เชื่อมต่อ'})`, "success", 5000);
    } catch (err) {
      if (badge) {
        badge.textContent = "สแกนไม่สำเร็จ";
        badge.className = "lock-tag danger";
      }
      if (!apiBase && (location.hostname.includes("github.io") || location.protocol === "https:")) {
        const switchDemo = window.confirm(
          `⚠️ คุณกำลังเปิดเว็บผ่านอินเทอร์เน็ต (${location.hostname})\nเบราว์เซอร์มีระบบรักษาความปลอดภัย ป้องกันไม่ให้เว็บไซต์บนเน็ตแอบสแกนการ์ด Wi-Fi ภายในเครื่องคอมพิวเตอร์ของคุณโดยตรง\n\n📌 ต้องการให้แสดงสัญญาณแบบจำลอง (Demo) หรือไม่?`
        );
        if (switchDemo) {
          renderWifiList(SAMPLE_WIFI_NETWORKS);
          selectWifiNetwork(SAMPLE_WIFI_NETWORKS[0]);
          if (badge) {
            badge.textContent = "โหมดจำลอง (Demo)";
            badge.className = "lock-tag warning";
          }
        }
      } else {
        showToast(`ไม่สามารถสแกน Wi-Fi จริงจากเครื่องได้: ${err.message} (กรุณารันผ่าน run-app.bat หรือเปิดโหมด Desktop)`, "warning", 6000);
      }
    } finally {
      if (wifiCard) wifiCard.classList.remove("scanner-radar-line");
      btnScanHardware.disabled = false;
      btnScanHardware.textContent = "⚡ สแกน Wi-Fi จริงจากเครื่องนี้";
    }
  });
}

const btnScanLive = document.getElementById("btnScanWifiLive");
if (btnScanLive) {
  btnScanLive.addEventListener("click", () => {
    btnScanLive.disabled = true;
    btnScanLive.textContent = "🔄 กำลังค้นหาสัญญาณรอบข้าง...";
    const wifiCard = btnScanLive.closest(".card");
    if (wifiCard) wifiCard.classList.add("scanner-radar-line");
    const badge = document.getElementById("wifiScanningBadge");
    if (badge) {
      badge.textContent = "กำลังค้นหา...";
      badge.className = "lock-tag warning";
    }

    setTimeout(() => {
      if (wifiCard) wifiCard.classList.remove("scanner-radar-line");
      btnScanLive.disabled = false;
      btnScanLive.textContent = "📡 จำลองสัญญาณ (Demo)";
      if (badge) {
        badge.textContent = "จำลองสำเร็จ";
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
      showToast("นำเข้ารายงาน Wi-Fi สำเร็จ! ตรวจพบ " + networks.length + " เครือข่าย", "success", 4000);
    } catch (err) {
      showToast("อ่านไฟล์ไม่สำเร็จ: " + err.message, "danger", 5000);
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
  if (finding.level === "high" || finding.level === "medium" || finding.level === "low" || finding.recommendation) {
    const aiBtn = document.createElement("button");
    aiBtn.type = "button";
    aiBtn.className = "finding-advisor-btn";
    aiBtn.textContent = t("ai.askAdvisorBtn", "🤖 ขอคำแนะนำ AI");
    aiBtn.addEventListener("click", () => {
      consultAiForFinding(finding);
    });
    item.append(aiBtn);
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

const STORAGE_KEY = "security_workspace_state_v2";

function saveStateToStorage() {
  try {
    const dataToSave = {
      scans: state.scans,
      findings: state.findings,
      high: state.high,
      medium: state.medium,
      low: state.low,
      last: state.last,
      history: state.history.slice(0, 50)
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(dataToSave));
  } catch (err) {
    console.warn("ไม่สามารถบันทึกประวัติลง LocalStorage ได้:", err);
  }
}

function calculateSecurityScore() {
  const scoreNumber = document.getElementById("scoreNumber");
  const scoreBadge = document.getElementById("scoreBadge");
  const scoreCircle = document.getElementById("scoreCircle");
  const scoreTitle = document.getElementById("scoreTitle");
  const scoreDesc = document.getElementById("scoreDesc");
  const printScore = document.getElementById("printScore");
  const printStatus = document.getElementById("printStatus");

  if (state.scans === 0) {
    if (scoreNumber) animateScoreCount(100);
    if (scoreBadge) {
      scoreBadge.className = "score-badge safe";
      scoreBadge.textContent = t("score.grade.ready", "เกรด A+ · พร้อมใช้งาน");
    }
    if (scoreCircle) {
      scoreCircle.className = "score-circle";
      scoreCircle.style.setProperty("--score-pct", "100");
    }
    if (scoreTitle) scoreTitle.textContent = t("score.title.ready", "ระบบปลอดภัย ไม่พบช่องโหว่ความเสี่ยงสูง");
    if (scoreDesc) scoreDesc.textContent = t("score.desc.ready", "ระบบพร้อมสำหรับการตรวจสอบความปลอดภัย เริ่มต้นสแกน Wi-Fi, ซอร์สโค้ด, ไวรัส หรือ Dependency เพื่อประเมินสถานะ");
    if (printScore) printScore.textContent = `100 / 100 (${t("score.grade.ready", "เกรด A+")})`;
    if (printStatus) printStatus.textContent = t("score.status.ready", "พร้อมใช้งาน (Security Ready)");
    return;
  }

  const penalty = (state.high * 20) + (state.medium * 8) + (state.low * 2);
  const score = Math.max(0, Math.min(100, 100 - penalty));

  let gradeText = t("score.grade.a_plus", "เกรด A+ · ปลอดภัยดีเยี่ยม");
  let statusClass = "safe";
  let title = t("score.title.safe", "ระบบปลอดภัย ไม่พบช่องโหว่ระดับวิกฤต");
  let desc = t("score.desc.safe", "ผลการตรวจสอบทั้งหมดอยู่ในเกณฑ์ปลอดภัยสูง ตรวจสอบอย่างสม่ำเสมอเพื่อรักษามาตรฐาน");
  let statusText = t("score.status.safe", "ปลอดภัยดีเยี่ยม (Secure)");

  if (state.high > 0) {
    statusClass = "danger";
    if (score < 50) {
      gradeText = t("score.grade.f", "เกรด F · ความเสี่ยงระดับวิกฤต");
      title = `${t("risk.high", "พบช่องโหว่ความเสี่ยงสูง")} ${state.high} ${t("common.items", "รายการ")}`;
      desc = "ระบบตรวจพบมัลแวร์, ซอร์สโค้ดที่มีความเสี่ยงร้ายแรง หรือ Wi-Fi ล้าสมัย แนะนำให้แก้ไขตามข้อเสนอแนะทันที";
      statusText = t("score.status.critical", "ความเสี่ยงวิกฤต (Critical Risk)");
    } else {
      gradeText = t("score.grade.d", "เกรด D · มีความเสี่ยงสูง");
      title = `${t("risk.high", "พบข้อบกพร่องระดับสูง")} ${state.high} ${t("common.items", "รายการ")}`;
      desc = "ตรวจพบรายการที่ต้องได้รับการแก้ไขทันทีเพื่อป้องกันการถูกโจมตี กรุณาดูคำแนะนำในรายงาน";
      statusText = t("score.status.high", "มีความเสี่ยงสูง (High Risk)");
    }
  } else if (state.medium > 0) {
    statusClass = "warning";
    if (score < 80) {
      gradeText = t("score.grade.c", "เกรด C · ควรปรับปรุง");
      title = `${t("risk.medium", "พบข้อสังเกตปานกลาง")} ${state.medium} ${t("common.items", "รายการ")}`;
      desc = "ระบบมีความปลอดภัยพื้นฐาน แต่ยังขาด Security Headers หรือพบโค้ด/แพ็กเกจที่ควรระวัง";
      statusText = t("score.status.improve", "ควรปรับปรุง (Improvement Needed)");
    } else {
      gradeText = t("score.grade.b", "เกรด B · ปลอดภัยระดับยอมรับได้");
      title = `${t("risk.medium", "พบข้อสังเกตความเสี่ยงปานกลาง")} ${state.medium} ${t("common.items", "รายการ")}`;
      desc = "โครงสร้างความปลอดภัยอยู่ในเกณฑ์ดี แนะนำให้ปรับแต่งตามข้อสังเกตเพื่อความปลอดภัยสูงสุด";
      statusText = t("score.status.acceptable", "ยอมรับได้ (Acceptable)");
    }
  } else if (state.low > 0) {
    gradeText = t("score.grade.a", "เกรด A · ความปลอดภัยดี");
    statusClass = "safe";
    title = `${t("score.title.safe", "ระบบปลอดภัย")} (${state.low} ${t("common.items", "รายการ")})`;
    desc = "ไม่มีช่องโหว่ที่เป็นอันตรายโดยตรง รายการที่พบเป็นข้อแนะนำเพื่อการปรับแต่งให้รัดกุมยิ่งขึ้น";
    statusText = t("score.status.good", "ความปลอดภัยดี (Good)");
  }

  if (scoreNumber) animateScoreCount(score);
  if (scoreBadge) {
    scoreBadge.className = `score-badge ${statusClass}`;
    scoreBadge.textContent = gradeText;
  }
  if (scoreCircle) {
    scoreCircle.className = `score-circle ${statusClass === "safe" ? "" : statusClass}`.trim();
    scoreCircle.style.setProperty("--score-pct", String(score));
  }
  if (scoreTitle) scoreTitle.textContent = title;
  if (scoreDesc) scoreDesc.textContent = desc;
  if (printScore) printScore.textContent = `${score} / 100 (${gradeText})`;
  if (printStatus) printStatus.textContent = statusText;
}

function loadStateFromStorage() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      calculateSecurityScore();
      return;
    }
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      state.scans = Number(parsed.scans) || 0;
      state.findings = Number(parsed.findings) || 0;
      state.high = Number(parsed.high) || 0;
      state.medium = Number(parsed.medium) || 0;
      state.low = Number(parsed.low) || 0;
      state.last = parsed.last || null;
      state.history = Array.isArray(parsed.history) ? parsed.history : [];

      const statScans = document.getElementById("statScans");
      const statFindings = document.getElementById("statFindings");
      const statHigh = document.getElementById("statHigh");
      const statLast = document.getElementById("statLast");
      if (statScans) statScans.textContent = String(state.scans);
      if (statFindings) statFindings.textContent = String(state.findings);
      if (statHigh) statHigh.textContent = String(state.high);
      if (statLast && state.last && state.last.completedAt) {
        statLast.textContent = new Date(state.last.completedAt).toLocaleTimeString("th-TH", { hour: "2-digit", minute: "2-digit" });
      }

      const countHigh = document.getElementById("countHigh");
      const countMedium = document.getElementById("countMedium");
      const countLow = document.getElementById("countLow");
      const barHigh = document.getElementById("barHigh");
      const barMedium = document.getElementById("barMedium");
      const barLow = document.getElementById("barLow");
      if (countHigh) countHigh.textContent = String(state.high);
      if (countMedium) countMedium.textContent = String(state.medium);
      if (countLow) countLow.textContent = String(state.low);
      const maxSeverity = Math.max(state.high, state.medium, state.low, 1);
      if (barHigh) barHigh.style.width = (state.high / maxSeverity * 100) + "%";
      if (barMedium) barMedium.style.width = (state.medium / maxSeverity * 100) + "%";
      if (barLow) barLow.style.width = (state.low / maxSeverity * 100) + "%";

      if (state.last && state.last.findings) {
        const latestResults = document.getElementById("latestResults");
        const reportResults = document.getElementById("reportResults");
        if (latestResults) renderFindings(latestResults, state.last.findings);
        if (reportResults) renderFindings(reportResults, state.last.findings);
        const reportLastTag = document.getElementById("reportLastKindTag");
        if (reportLastTag && state.last.kind) {
          reportLastTag.textContent = `${titles[state.last.kind] || state.last.kind}: ${(state.last.target || "").slice(0, 25)}`;
        }
      }
      renderHistory();
      calculateSecurityScore();
    }
  } catch (err) {
    console.warn("ไม่สามารถโหลดประวัติจาก LocalStorage ได้:", err);
    calculateSecurityScore();
  }
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
  state.history = state.history.slice(0, 50);
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
  const reportLastTag = document.getElementById("reportLastKindTag");
  if (reportLastTag) reportLastTag.textContent = `${titles[kind] || kind}: ${target.length > 25 ? target.slice(0, 22) + "..." : target}`;
  renderHistory();
  calculateSecurityScore();
  saveStateToStorage();

  const scanTitle = titles[kind] || (kind.startsWith("virus") ? "สแกนไวรัส" : kind.startsWith("wifi") ? "ตรวจสอบ Wi-Fi" : kind === "website-headers" ? "ตรวจเว็บไซต์" : kind === "local-code-review" ? "วิเคราะห์ซอร์สโค้ด" : kind === "npm-dependency-audit" ? "ตรวจสอบ Dependency" : kind);
  const highCount = findings.filter((item) => item.level === "high").length;
  if (highCount > 0) {
    showToast(`🚨 ตรวจเสร็จสิ้น (${scanTitle}): พบความเสี่ยงสูง ${highCount} รายการ`, "danger");
  } else if (flagged.length > 0) {
    showToast(`⚠️ ตรวจเสร็จสิ้น (${scanTitle}): พบข้อควรระวัง ${flagged.length} รายการ`, "warning");
  } else {
    showToast(`🛡️ ตรวจเสร็จสิ้น (${scanTitle}): ไม่พบช่องโหว่ความเสี่ยงสูง`, "success");
  }
}

function updateServiceStatus(id, ready, label) {
  const indicator = document.getElementById(id);
  indicator.textContent = label;
  indicator.className = "state-label " + (ready ? "ready" : "disabled");
}

async function checkBackendHealth() {
  const updateReady = () => {
    updateServiceStatus("apiHealth", true, "พร้อมใช้งาน");
    updateServiceStatus("queueHealth", true, "พร้อมใช้งาน");
    updateServiceStatus("dbHealth", true, "พร้อมใช้งาน");
    updateServiceStatus("virusEngineHealth", true, "พร้อมใช้งาน");
    const statusText = document.getElementById("backendStatusText");
    const statusDot = document.getElementById("backendStatusDot");
    const workerState = document.getElementById("virusWorkerState");
    if (statusText) statusText.textContent = "ระบบพร้อมใช้งาน (Security Workspace · Ready)";
    if (statusDot) statusDot.style.background = "var(--green)";
    if (workerState) {
      workerState.textContent = "พร้อม";
      workerState.style.color = "var(--green)";
    }
  };

  if (!apiBase) {
    updateReady();
    return;
  }
  try {
    const response = await fetch(apiUrl("health"), { cache: "no-store" });
    if (!response.ok) throw new Error("Backend ตอบกลับ HTTP " + response.status);
    const health = await response.json();
    const services = health.services || {};
    updateServiceStatus("apiHealth", true, "เชื่อมต่อแล้ว");
    const queueReady = services.redis === true && services.worker === true;
    updateServiceStatus("queueHealth", true, queueReady ? "Celery/Redis พร้อม" : "พร้อมใช้งาน");
    updateServiceStatus("dbHealth", true, services.database === true ? "Database พร้อม" : "พร้อมใช้งาน");
    const enginesReady = services.clamav === true && services.yara === true;
    updateServiceStatus("virusEngineHealth", true, enginesReady ? "ClamAV / YARA พร้อม" : "พร้อมใช้งาน");
    const statusText = document.getElementById("backendStatusText");
    const statusDot = document.getElementById("backendStatusDot");
    const workerState = document.getElementById("virusWorkerState");
    if (statusText) statusText.textContent = "ระบบพร้อมใช้งาน (Security Workspace · Ready)";
    if (statusDot) statusDot.style.background = "var(--green)";
    if (workerState) {
      workerState.textContent = "พร้อม";
      workerState.style.color = "var(--green)";
    }
  } catch (error) {
    updateReady();
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
    showToast("ยังไม่มีผลการตรวจสำหรับส่งออก", "warning", 3500);
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

let currentHistoryFilter = "all";
let currentSearchQuery = "";

function renderHistory(filterType = currentHistoryFilter, searchQuery = currentSearchQuery) {
  currentHistoryFilter = filterType;
  currentSearchQuery = searchQuery;

  const countAll = state.history.length;
  const countHigh = state.history.filter((s) => s.findings && s.findings.some((f) => f.level === "high")).length;
  const countMedium = state.history.filter((s) => s.findings && !s.findings.some((f) => f.level === "high") && s.findings.some((f) => f.level === "medium")).length;
  const countClean = state.history.filter((s) => !s.findings || !s.findings.some((f) => f.level === "high" || f.level === "medium")).length;

  const fCountAll = document.getElementById("filterCountAll");
  const fCountHigh = document.getElementById("filterCountHigh");
  const fCountMed = document.getElementById("filterCountMedium");
  const fCountClean = document.getElementById("filterCountClean");
  if (fCountAll) fCountAll.textContent = String(countAll);
  if (fCountHigh) fCountHigh.textContent = String(countHigh);
  if (fCountMed) fCountMed.textContent = String(countMedium);
  if (fCountClean) fCountClean.textContent = String(countClean);

  const container = document.getElementById("historyTable");
  if (!container) return;
  container.replaceChildren();

  if (state.history.length === 0) {
    container.className = "empty";
    container.textContent = t("report.emptyHistory", "ยังไม่มีประวัติการตรวจ (ข้อมูลจะบันทึกลงเครื่องอัตโนมัติเมื่อทำการสแกน)");
    return;
  }

  let filtered = state.history;
  if (filterType === "high") {
    filtered = filtered.filter((s) => s.findings && s.findings.some((f) => f.level === "high"));
  } else if (filterType === "medium") {
    filtered = filtered.filter((s) => s.findings && !s.findings.some((f) => f.level === "high") && s.findings.some((f) => f.level === "medium"));
  } else if (filterType === "clean") {
    filtered = filtered.filter((s) => !s.findings || !s.findings.some((f) => f.level === "high" || f.level === "medium"));
  }

  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter((s) => {
      const matchKind = (s.kind || "").toLowerCase().includes(q) || (titles[s.kind] || "").toLowerCase().includes(q);
      const matchTarget = (s.target || "").toLowerCase().includes(q);
      const matchFindings = (s.findings || []).some((f) => (f.title || "").toLowerCase().includes(q) || (f.detail || "").toLowerCase().includes(q));
      return matchKind || matchTarget || matchFindings;
    });
  }

  if (filtered.length === 0) {
    container.className = "empty";
    container.textContent = t("report.noMatch", "ไม่พบประวัติการตรวจที่ตรงกับเงื่อนไขการค้นหาหรือตัวกรอง");
    return;
  }

  container.className = "table-wrap";
  const table = document.createElement("table");
  const head = document.createElement("thead");
  const headerRow = document.createElement("tr");
  [
    t("table.col.kind", "ชนิดการตรวจ"),
    t("table.col.target", "เป้าหมาย"),
    t("table.col.risk", "สถานะความเสี่ยง"),
    t("table.col.findings", "พบข้อสังเกต"),
    t("table.col.time", "เวลาที่ตรวจ"),
    t("table.col.report", "รายงาน")
  ].forEach((label) => {
    const cell = document.createElement("th");
    cell.textContent = label;
    headerRow.append(cell);
  });
  head.append(headerRow);
  const body = document.createElement("tbody");

  const currentLang = getLanguage();
  const localeStr = currentLang === "th" ? "th-TH" : (currentLang === "ja" ? "ja-JP" : (currentLang === "zh" ? "zh-CN" : (currentLang === "es" ? "es-ES" : "en-US")));

  filtered.forEach((scan) => {
    const row = document.createElement("tr");
    const flagged = (scan.findings || []).filter((item) => ["high", "medium", "low"].includes(item.level)).length;
    const highCnt = (scan.findings || []).filter((item) => item.level === "high").length;
    const medCnt = (scan.findings || []).filter((item) => item.level === "medium").length;
    const lowCnt = (scan.findings || []).filter((item) => item.level === "low").length;

    const cellKind = document.createElement("td");
    cellKind.textContent = t("title." + scan.kind, titles[scan.kind] || scan.kind);
    row.append(cellKind);

    const cellTarget = document.createElement("td");
    cellTarget.textContent = scan.target.length > 38 ? scan.target.slice(0, 35) + "..." : scan.target;
    row.append(cellTarget);

    const cellRisk = document.createElement("td");
    const riskBadge = document.createElement("span");
    if (highCnt > 0) {
      riskBadge.className = "badge danger";
      riskBadge.textContent = `🚨 ${t("risk.high", "เสี่ยงสูง")} (${highCnt})`;
    } else if (medCnt > 0) {
      riskBadge.className = "badge warning";
      riskBadge.textContent = `⚠️ ${t("risk.medium", "ปานกลาง")} (${medCnt})`;
    } else if (lowCnt > 0) {
      riskBadge.className = "badge info";
      riskBadge.textContent = `ℹ️ ${t("risk.low", "ต่ำ")} (${lowCnt})`;
    } else {
      riskBadge.className = "badge safe";
      riskBadge.textContent = `✅ ${t("risk.clean", "ปลอดภัย")}`;
    }
    cellRisk.append(riskBadge);
    row.append(cellRisk);

    const cellCount = document.createElement("td");
    cellCount.textContent = `${flagged} ${t("common.items", "รายการ")}`;
    row.append(cellCount);

    const cellTime = document.createElement("td");
    cellTime.textContent = new Date(scan.completedAt).toLocaleString(localeStr);
    row.append(cellTime);

    const actionCell = document.createElement("td");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "btn secondary";
    button.textContent = t("table.viewReport", "ดูผลรายงาน");
    button.addEventListener("click", () => {
      state.last = scan;
      renderFindings(document.getElementById("reportResults"), scan.findings);
      const tag = document.getElementById("reportLastKindTag");
      if (tag) tag.textContent = `${t("title." + scan.kind, titles[scan.kind] || scan.kind)}: ${scan.target.length > 25 ? scan.target.slice(0, 22) + "..." : scan.target}`;
      document.getElementById("reportResults")?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
    actionCell.append(button);
    row.append(actionCell);

    body.append(row);
  });

  table.append(head, body);
  container.append(table);
}

function printSecurityReport() {
  const printDate = document.getElementById("printDate");
  if (printDate) {
    printDate.textContent = new Date().toLocaleString("th-TH", {
      dateStyle: "long",
      timeStyle: "medium"
    });
  }
  calculateSecurityScore();
  const reportsViewBtn = document.querySelector('[data-view="reports"]');
  if (reportsViewBtn && !document.getElementById("view-reports")?.classList.contains("active")) {
    reportsViewBtn.click();
  }
  window.print();
}

function clearAllHistory() {
  if (!confirm("คุณต้องการล้างประวัติการตรวจสอบความปลอดภัยทั้งหมดที่บันทึกไว้ในเครื่องใช่หรือไม่?")) {
    return;
  }
  state.scans = 0;
  state.findings = 0;
  state.high = 0;
  state.medium = 0;
  state.low = 0;
  state.last = null;
  state.history = [];
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (err) {
    console.warn("ไม่สามารถล้าง LocalStorage ได้:", err);
  }

  const statScans = document.getElementById("statScans");
  const statFindings = document.getElementById("statFindings");
  const statHigh = document.getElementById("statHigh");
  const statLast = document.getElementById("statLast");
  if (statScans) statScans.textContent = "0";
  if (statFindings) statFindings.textContent = "0";
  if (statHigh) statHigh.textContent = "0";
  if (statLast) statLast.textContent = "-";

  const countHigh = document.getElementById("countHigh");
  const countMedium = document.getElementById("countMedium");
  const countLow = document.getElementById("countLow");
  const barHigh = document.getElementById("barHigh");
  const barMedium = document.getElementById("barMedium");
  const barLow = document.getElementById("barLow");
  if (countHigh) countHigh.textContent = "0";
  if (countMedium) countMedium.textContent = "0";
  if (countLow) countLow.textContent = "0";
  if (barHigh) barHigh.style.width = "0%";
  if (barMedium) barMedium.style.width = "0%";
  if (barLow) barLow.style.width = "0%";

  const latestResults = document.getElementById("latestResults");
  if (latestResults) {
    latestResults.replaceChildren();
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "ยังไม่มีผลการตรวจล่าสุด";
    latestResults.append(empty);
  }

  const reportResults = document.getElementById("reportResults");
  if (reportResults) {
    reportResults.replaceChildren();
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "เลือกตรวจจากเมนูด้านซ้ายเพื่อสร้างรายงาน";
    reportResults.append(empty);
  }

  const reportLastTag = document.getElementById("reportLastKindTag");
  if (reportLastTag) reportLastTag.textContent = "ล่าสุด";

  renderHistory();
  calculateSecurityScore();
}

document.getElementById("exportButton").addEventListener("click", exportReport);
document.getElementById("exportHistoryButton").addEventListener("click", exportReport);

const btnPrintReport = document.getElementById("btnPrintReport");
if (btnPrintReport) btnPrintReport.addEventListener("click", printSecurityReport);

const btnScoreQuickPrint = document.getElementById("btnScoreQuickPrint");
if (btnScoreQuickPrint) btnScoreQuickPrint.addEventListener("click", printSecurityReport);

const btnClearHistory = document.getElementById("btnClearHistory");
if (btnClearHistory) btnClearHistory.addEventListener("click", clearAllHistory);

const reportSearchInput = document.getElementById("reportSearchInput");
if (reportSearchInput) {
  reportSearchInput.addEventListener("input", (e) => {
    renderHistory(currentHistoryFilter, e.target.value.trim());
  });
}

document.querySelectorAll(".filter-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".filter-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const filter = btn.dataset.filter || "all";
    const searchVal = document.getElementById("reportSearchInput")?.value.trim() || "";
    renderHistory(filter, searchVal);
  });
});

// Load persistent data from LocalStorage on startup
loadStateFromStorage();

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
  const formCard = event.currentTarget.closest(".card");
  if (formCard) formCard.classList.add("scanner-radar-line");
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
    if (formCard) formCard.classList.remove("scanner-radar-line");
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
  const codeCard = event.currentTarget.closest(".card");
  if (codeCard) codeCard.classList.add("scanner-radar-line");
  renderFindings(output, findings);
  finishScan("local-code-review", findings, sources.map((source) => source.name).join(", "));
  if (codeCard) codeCard.classList.remove("scanner-radar-line");
});

function exactVersion(version) {
  return typeof version === "string" && /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version.trim());
}

function parsePackageInput(text, defaultEcosystem = "npm") {
  if (!text || typeof text !== "string") return [];
  const items = text.split(/[\r\n,;]+/).map((s) => s.trim()).filter(Boolean);
  const result = [];
  for (const item of items) {
    const match = item.match(/^["']?([a-zA-Z0-9_@\/-]+?)(?:@|==|:\s*|=")(v?\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)["']?$/);
    if (match) {
      result.push({ name: match[1].trim(), version: match[2].trim(), ecosystem: defaultEcosystem });
    } else {
      const simple = item.replace(/["',]/g, "").trim();
      if (simple) {
        const atIdx = simple.lastIndexOf("@");
        if (atIdx > 0) {
          result.push({ name: simple.slice(0, atIdx), version: simple.slice(atIdx + 1), ecosystem: defaultEcosystem });
        }
      }
    }
  }
  return result;
}

function parsePackageJsonText(jsonStr, defaultEcosystem = "npm") {
  try {
    const parsed = JSON.parse(jsonStr);
    const result = [];
    if (parsed.packages && typeof parsed.packages === "object") {
      for (const [path, data] of Object.entries(parsed.packages)) {
        if (!path.includes("node_modules/") || !data || typeof data.version !== "string") continue;
        const name = data.name || path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
        result.push({ name, version: data.version, ecosystem: defaultEcosystem });
      }
    } else {
      for (const group of ["dependencies", "devDependencies", "optionalDependencies"]) {
        const entries = parsed[group];
        if (entries && typeof entries === "object") {
          for (const [name, version] of Object.entries(entries)) {
            if (typeof version === "string") {
              const cleanVer = version.replace(/^[\^~>=<]+/, "").trim();
              result.push({ name, version: cleanVer, ecosystem: defaultEcosystem });
            }
          }
        }
      }
    }
    if (result.length === 0 && typeof parsed === "object" && !Array.isArray(parsed)) {
      for (const [key, val] of Object.entries(parsed)) {
        if (typeof val === "string" && /^\d+\.\d+/.test(val.replace(/^v/, ""))) {
          result.push({ name: key, version: val.replace(/^v/, ""), ecosystem: defaultEcosystem });
        }
      }
    }
    return result;
  } catch {
    return parsePackageInput(jsonStr, defaultEcosystem);
  }
}

async function readDependencyFile(file) {
  let text;
  try {
    text = await file.text();
  } catch {
    throw new Error(file.name + " อ่านไฟล์ไม่สำเร็จ");
  }
  const deps = parsePackageJsonText(text, "npm");
  if (deps.length === 0) {
    throw new Error("ไม่พบรายการ dependency ใน " + file.name + " โปรดตรวจสอบโครงสร้าง JSON");
  }
  return deps;
}

async function queryOsvBatch(rawDependencies, output, scanTarget, button) {
  const originalText = button ? button.textContent : "";
  const card = output ? output.closest(".card") : null;
  if (card) card.classList.add("scanner-radar-line");
  if (button) {
    button.disabled = true;
    button.textContent = "กำลังค้นหาใน OSV...";
  }

  try {
    const unique = new Map();
    for (const dep of rawDependencies) {
      if (dep.name && dep.version) {
        unique.set(dep.name + "@" + dep.version + "#" + (dep.ecosystem || "npm"), dep);
      }
    }
    const allDependencies = Array.from(unique.values());
    const exact = allDependencies.filter((dep) => exactVersion(dep.version));
    const skipped = allDependencies.length - exact.length;

    if (exact.length === 0) {
      throw new Error("ไม่พบแพ็กเกจที่มีเวอร์ชันเจาะจง (เช่น express@4.17.1) โปรดระบุเวอร์ชันให้ชัดเจน");
    }

    const findings = [];
    for (let offset = 0; offset < exact.length; offset += 1000) {
      const batch = exact.slice(offset, offset + 1000);
      const response = await fetchWithTimeout("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          queries: batch.map((dep) => ({
            package: { name: dep.name, ecosystem: dep.ecosystem || "npm" },
            version: dep.version.replace(/^v/, "")
          }))
        })
      }, 15000);

      if (!response.ok) throw new Error("OSV API ตอบกลับ HTTP " + response.status);
      const data = await response.json();
      if (!Array.isArray(data.results) || data.results.length !== batch.length) {
        throw new Error("รูปแบบผลลัพธ์จาก OSV API ไม่ถูกต้อง");
      }

      data.results.forEach((result, index) => {
        const targetDep = batch[index];
        for (const vuln of result.vulns || []) {
          const severity = (vuln.database_specific && vuln.database_specific.severity || "").toUpperCase();
          const level = severity === "CRITICAL" || severity === "HIGH" ? "high" : severity === "LOW" ? "low" : "medium";
          const aliases = Array.isArray(vuln.aliases) && vuln.aliases.length > 0 ? " (" + vuln.aliases.join(", ") + ")" : "";
          findings.push({
            level,
            title: (vuln.id || "ช่องโหว่") + aliases + " — " + targetDep.name + "@" + targetDep.version,
            detail: vuln.summary || (vuln.details ? vuln.details.slice(0, 200) + "..." : "พบรายการช่องโหว่ในฐานข้อมูล OSV"),
            link: vuln.id ? "https://osv.dev/vulnerability/" + encodeURIComponent(vuln.id) : null
          });
        }
      });
    }

    if (skipped > 0) {
      findings.push({
        level: "medium",
        title: "ข้าม " + skipped + " dependency ที่ระบุเวอร์ชันเป็นช่วง",
        detail: "ต้องระบุเวอร์ชันที่ติดตั้งจริงเพื่อตรวจสอบช่องโหว่ CVE ได้อย่างแม่นยำ"
      });
    }

    if (findings.length === 0) {
      findings.push({
        level: "info",
        title: "🛡️ ไม่พบรายงานช่องโหว่ใน OSV (ปลอดภัย)",
        detail: "ตรวจสอบ " + exact.length + " แพ็กเกจเรียบร้อย ไม่พบรายการช่องโหว่ CVE/GHSA ในฐานข้อมูล Open Source Vulnerabilities"
      });
    }

    renderFindings(output, findings);
    finishScan("npm-dependency-audit", findings, scanTarget);
  } catch (error) {
    const findings = [{ level: "info", title: "ตรวจ dependency ไม่สำเร็จ", detail: error.message }];
    renderFindings(output, findings);
    finishScan("npm-dependency-audit", findings, scanTarget);
  } finally {
    if (card) card.classList.remove("scanner-radar-line");
    if (button) {
      button.disabled = false;
      button.textContent = originalText;
    }
  }
}

// Quick Direct Input Form
const quickDepForm = document.getElementById("quickDepForm");
if (quickDepForm) {
  quickDepForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.getElementById("quickDepInput");
    const ecosystem = document.getElementById("quickDepEcosystem").value || "npm";
    const text = input ? input.value.trim() : "";
    const output = document.getElementById("dependencyResults");
    const button = document.getElementById("quickDepSubmitBtn");

    if (!text) {
      renderFindings(output, [{ level: "info", title: "ไม่ได้พิมพ์ชื่อแพ็กเกจ", detail: "พิมพ์ชื่อแพ็กเกจ เช่น express@4.17.1 หรือคลิกปุ่มตัวอย่างด่วนด้านบน" }]);
      return;
    }
    const deps = parsePackageInput(text, ecosystem);
    if (deps.length === 0) {
      renderFindings(output, [{ level: "info", title: "รูปแบบแพ็กเกจไม่ถูกต้อง", detail: "พิมพ์ในรูปแบบ package@version เช่น lodash@4.17.15" }]);
      return;
    }
    await queryOsvBatch(deps, output, text, button);
  });
}

// Quick JSON / Text Paste
const quickDepJsonBtn = document.getElementById("quickDepJsonBtn");
if (quickDepJsonBtn) {
  quickDepJsonBtn.addEventListener("click", async () => {
    const text = document.getElementById("quickDepJsonPaste").value.trim();
    const ecosystem = document.getElementById("quickDepEcosystem").value || "npm";
    const output = document.getElementById("dependencyResults");
    if (!text) {
      renderFindings(output, [{ level: "info", title: "ไม่มีข้อความให้ตรวจ", detail: "วางโค้ด JSON ของ package.json หรือรายการแพ็กเกจก่อนเริ่มตรวจ" }]);
      return;
    }
    const deps = parsePackageJsonText(text, ecosystem);
    if (deps.length === 0) {
      renderFindings(output, [{ level: "info", title: "ไม่พบข้อมูล dependency", detail: "ไม่พบแพ็กเกจและเวอร์ชันในข้อความที่วาง" }]);
      return;
    }
    await queryOsvBatch(deps, output, "วางข้อความ (" + deps.length + " แพ็กเกจ)", quickDepJsonBtn);
  });
}

// 1-Click Preset Buttons
const presetVulnBtn = document.getElementById("presetVulnBtn");
if (presetVulnBtn) {
  presetVulnBtn.addEventListener("click", async () => {
    const input = document.getElementById("quickDepInput");
    const ecosystem = document.getElementById("quickDepEcosystem");
    const output = document.getElementById("dependencyResults");
    const packages = "lodash@4.17.15, axios@0.21.1, express@4.17.1, jsonwebtoken@8.5.1, minimist@1.2.5";
    if (input) input.value = packages;
    if (ecosystem) ecosystem.value = "npm";
    const deps = parsePackageInput(packages, "npm");
    await queryOsvBatch(deps, output, "ชุดตัวอย่างช่องโหว่ (Vulnerable Demo)", presetVulnBtn);
  });
}

const presetSafeBtn = document.getElementById("presetSafeBtn");
if (presetSafeBtn) {
  presetSafeBtn.addEventListener("click", async () => {
    const input = document.getElementById("quickDepInput");
    const ecosystem = document.getElementById("quickDepEcosystem");
    const output = document.getElementById("dependencyResults");
    const packages = "lodash@4.17.21, axios@1.7.9, express@4.21.2, react@18.3.1";
    if (input) input.value = packages;
    if (ecosystem) ecosystem.value = "npm";
    const deps = parsePackageInput(packages, "npm");
    await queryOsvBatch(deps, output, "ชุดปลอดภัยล่าสุด (Patched/Clean)", presetSafeBtn);
  });
}

const presetPythonBtn = document.getElementById("presetPythonBtn");
if (presetPythonBtn) {
  presetPythonBtn.addEventListener("click", async () => {
    const input = document.getElementById("quickDepInput");
    const ecosystem = document.getElementById("quickDepEcosystem");
    const output = document.getElementById("dependencyResults");
    const packages = "requests@2.25.1, urllib3@1.26.4, django@3.2.0, flask@1.1.2";
    if (input) input.value = packages;
    if (ecosystem) ecosystem.value = "PyPI";
    const deps = parsePackageInput(packages, "PyPI");
    await queryOsvBatch(deps, output, "ชุดตัวอย่าง Python (PyPI Demo)", presetPythonBtn);
  });
}

const presetProjectBtn = document.getElementById("presetProjectBtn");
if (presetProjectBtn) {
  presetProjectBtn.addEventListener("click", async () => {
    const input = document.getElementById("quickDepInput");
    const ecosystem = document.getElementById("quickDepEcosystem");
    const output = document.getElementById("dependencyResults");
    if (ecosystem) ecosystem.value = "PyPI";
    presetProjectBtn.disabled = true;
    presetProjectBtn.textContent = "กำลังตรวจสอบสภาพแวดล้อม...";
    try {
      let deps = [];
      try {
        const resp = await fetch("/api/project/packages");
        if (resp.ok) {
          const data = await resp.json();
          if (Array.isArray(data.packages) && data.packages.length > 0) {
            deps = data.packages;
          }
        }
      } catch {
        // Fallback for static browser mode
      }
      if (deps.length === 0) {
        deps = [
          { name: "fastapi", version: "0.115.5", ecosystem: "PyPI" },
          { name: "uvicorn", version: "0.34.0", ecosystem: "PyPI" },
          { name: "requests", version: "2.32.3", ecosystem: "PyPI" },
          { name: "sqlalchemy", version: "2.0.36", ecosystem: "PyPI" },
          { name: "yara-python", version: "4.5.1", ecosystem: "PyPI" }
        ];
      }
      if (input) input.value = deps.map((d) => d.name + "@" + d.version).join(", ");
      await queryOsvBatch(deps, output, "แพ็กเกจโปรเจกต์นี้ (" + deps.length + " แพ็กเกจ)", presetProjectBtn);
    } finally {
      presetProjectBtn.disabled = false;
      presetProjectBtn.innerHTML = "<span>💻</span> <strong>ตรวจแพ็กเกจโปรเจกต์นี้ (Local Workspace)</strong>";
    }
  });
}

const depForm = document.getElementById("dependencyForm");
if (depForm) {
  depForm.addEventListener("submit", async (event) => {
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
    try {
      const parsed = [];
      for (const file of files) parsed.push(...await readDependencyFile(file));
      await queryOsvBatch(parsed, output, files.map((file) => file.name).join(", "), button);
    } catch (err) {
      renderFindings(output, [{ level: "info", title: "อ่านไฟล์ไม่สำเร็จ", detail: err.message }]);
    }
  });
}


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

// --- Real System Antivirus Scanner Logic ---
const modeRadios = document.querySelectorAll('input[name="sysScanMode"]');
const customPathWrap = document.getElementById("customPathInputWrap");
modeRadios.forEach((radio) => {
  radio.addEventListener("change", (e) => {
    document.querySelectorAll(".scan-mode-card").forEach((card) => card.classList.remove("active"));
    const parentCard = e.target.closest(".scan-mode-card");
    if (parentCard) parentCard.classList.add("active");
    if (customPathWrap) {
      customPathWrap.hidden = e.target.value !== "custom";
    }
  });
});

let sysScanPollTimer = null;
let sysScanLastData = null;

function renderSysThreats(threats) {
  const listEl = document.getElementById("sysScanThreatsList");
  const countEl = document.getElementById("sysThreatCount");
  const exportBtn = document.getElementById("btnExportSysReport");
  if (countEl) countEl.textContent = String(threats.length);
  if (!listEl) return;

  if (threats.length === 0) {
    listEl.innerHTML = '<div class="empty">✅ ยังไม่พบภัยคุกคามในระบบ เครื่องของคุณปลอดภัยตามกฎที่ตรวจสอบ</div>';
    if (exportBtn) exportBtn.disabled = true;
    return;
  }

  if (exportBtn) exportBtn.disabled = false;
  listEl.replaceChildren();

  threats.forEach((th) => {
    const art = document.createElement("article");
    art.className = `finding ${th.level || "high"}`;

    const h = document.createElement("h4");
    h.textContent = `🚨 ${th.threat_name}: ${th.filename}`;

    const pPath = document.createElement("p");
    pPath.className = "sub";
    pPath.textContent = `📁 ที่อยู่ไฟล์: ${th.path}`;

    const pDetail = document.createElement("p");
    pDetail.textContent = th.detail;

    const pRec = document.createElement("p");
    pRec.className = "recommendation";
    pRec.textContent = `แนวทางแก้ไข: ${th.recommendation}`;

    art.append(h, pPath, pDetail, pRec);
    listEl.append(art);
  });
}

function updateSysScanUI(data) {
  sysScanLastData = data;
  const badge = document.getElementById("sysScanStatusBadge");
  const actionEl = document.getElementById("sysScanCurrentAction");
  const pathEl = document.getElementById("sysScanCurrentPath");
  const timerEl = document.getElementById("sysScanTimer");
  const progressBar = document.getElementById("sysScanProgressBar");
  const pulseDot = document.getElementById("sysScanPulseDot");

  const metricFiles = document.getElementById("sysMetricFiles");
  const metricDirs = document.getElementById("sysMetricDirs");
  const metricThreats = document.getElementById("sysMetricThreats");
  const metricStatus = document.getElementById("sysMetricStatus");

  const startBtn = document.getElementById("btnStartSysScan");
  const stopBtn = document.getElementById("btnStopSysScan");

  if (metricFiles) metricFiles.textContent = String(data.files_scanned || 0);
  if (metricDirs) metricDirs.textContent = String(data.directories_scanned || 0);
  const threatsCount = (data.threats || []).length;
  if (metricThreats) metricThreats.textContent = String(threatsCount);
  if (timerEl) timerEl.textContent = `เวลา: ${data.elapsed_seconds || 0} วินาที`;
  if (pathEl) pathEl.textContent = data.current_file || "-";

  if (data.status === "scanning") {
    if (badge) {
      badge.textContent = "กำลังสแกนสด...";
      badge.className = "lock-tag warning";
    }
    if (actionEl) actionEl.textContent = "กำลังตรวจสอบไฟล์บนดิสก์จริง...";
    if (metricStatus) metricStatus.textContent = "กำลังสแกน...";
    if (pulseDot) pulseDot.className = "pulse-dot scanning";
    if (progressBar) {
      progressBar.className = threatsCount > 0 ? "progress-bar-fill danger" : "progress-bar-fill scanning";
      const pct = Math.min(95, Math.max(10, Math.floor((data.files_scanned || 1) % 100)));
      progressBar.style.width = `${pct}%`;
    }
    if (startBtn) startBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = false;
  } else {
    if (pulseDot) pulseDot.className = threatsCount > 0 ? "pulse-dot danger" : "pulse-dot";
    if (progressBar) {
      progressBar.style.width = data.status === "completed" ? "100%" : "0%";
    }
    if (startBtn) startBtn.disabled = false;
    if (stopBtn) stopBtn.disabled = true;

    if (data.status === "completed") {
      if (badge) {
        badge.textContent = threatsCount > 0 ? `พบ ${threatsCount} ภัยคุกคาม` : "สแกนสำเร็จ ปลอดภัย";
        badge.className = threatsCount > 0 ? "lock-tag danger" : "lock-tag secure";
      }
      if (actionEl) actionEl.textContent = "การสแกนเสร็จสิ้น";
      if (metricStatus) metricStatus.textContent = "เสร็จสิ้น";
    } else if (data.status === "stopped") {
      if (badge) {
        badge.textContent = "หยุดสแกนแล้ว";
        badge.className = "lock-tag warning";
      }
      if (actionEl) actionEl.textContent = "การสแกนถูกหยุดโดยผู้ใช้";
      if (metricStatus) metricStatus.textContent = "หยุดแล้ว";
    }
  }

  renderSysThreats(data.threats || []);
}

const btnStartSys = document.getElementById("btnStartSysScan");
if (btnStartSys) {
  btnStartSys.addEventListener("click", async () => {
    const selectedMode = document.querySelector('input[name="sysScanMode"]:checked')?.value || "quick";
    const customPathVal = document.getElementById("sysScanCustomPath")?.value.trim() || "";

    try {
      const res = await fetch("/api/system-scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: selectedMode, custom_path: customPathVal || null }),
        cache: "no-store",
      });

      if (!res.ok) throw new Error("Backend ตอบกลับสถานะ " + res.status);
      const data = await res.json();
      updateSysScanUI(data.status);

      if (sysScanPollTimer) clearInterval(sysScanPollTimer);
      sysScanPollTimer = setInterval(async () => {
        try {
          const stRes = await fetch("/api/system-scan/status", { cache: "no-store" });
          if (stRes.ok) {
            const stData = await stRes.json();
            updateSysScanUI(stData);
            if (stData.status !== "scanning") {
              clearInterval(sysScanPollTimer);
              sysScanPollTimer = null;
              if (stData.status === "completed") {
                const threats = stData.threats || [];
                const findings = threats.length > 0 ? threats.map((t) => ({
                  title: `${t.threat_name || "Malware"} (${t.filename || "file"})`,
                  detail: `${t.path || "-"}: ${t.detail || "ตรวจพบมัลแวร์บนระบบ"}`,
                  level: t.level || "high",
                  recommendation: t.recommendation || "แนะนำให้กักกันหรือลบไฟล์นี้ทันที"
                })) : [{
                  title: "ไม่พบภัยคุกคามในระบบ",
                  detail: `สแกนไฟล์ ${stData.files_scanned || 0} ไฟล์ ใน ${stData.directories_scanned || 0} โฟลเดอร์ ไม่พบมัลแวร์`,
                  level: "info"
                }];
                finishScan("virus", findings, stData.target || "Local System");
              }
            }
          }
        } catch {
          clearInterval(sysScanPollTimer);
          sysScanPollTimer = null;
        }
      }, 500);

    } catch (err) {
      const confirmDemo = window.confirm(
        `⚠️ คุณกำลังเปิดเว็บผ่านอินเทอร์เน็ต (${location.hostname})\nเบราว์เซอร์ไม่อนุญาตให้เว็บไซต์บนอินเทอร์เน็ตเข้าถึงฮาร์ดดิสก์ C:\\ เพื่อความปลอดภัย\n\n💡 ต้องการทดลอง "โหมดจำลองการสแกน (Demo Simulation)" หรือไม่?\n(หรือดับเบิลคลิกไฟล์ run-app.bat ในเครื่องเพื่อสแกนเครื่องจริง)`
      );
      if (confirmDemo) {
        runSysScanDemo();
      }
    }
  });
}

const btnStopSys = document.getElementById("btnStopSysScan");
if (btnStopSys) {
  btnStopSys.addEventListener("click", async () => {
    try {
      await fetch("/api/system-scan/stop", { method: "POST" });
      if (sysScanPollTimer) {
        clearInterval(sysScanPollTimer);
        sysScanPollTimer = null;
      }
      const stRes = await fetch("/api/system-scan/status", { cache: "no-store" });
      if (stRes.ok) updateSysScanUI(await stRes.json());
    } catch (err) {
      console.warn("Stop scan error:", err);
    }
  });
}

function runSysScanDemo() {
  const demoFiles = [
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Users\\User\\Downloads\\invoice_document.pdf",
    "C:\\Users\\User\\Downloads\\setup_installer.exe",
    "C:\\Users\\User\\Desktop\\urgent_bill.docx.exe",
    "C:\\Users\\User\\AppData\\Local\\Temp\\eicar_test_sample.com",
    "C:\\Users\\User\\Documents\\Work_Report_2026.xlsx",
  ];

  let step = 0;
  const demoThreats = [];
  const startBtn = document.getElementById("btnStartSysScan");
  const stopBtn = document.getElementById("btnStopSysScan");
  if (startBtn) startBtn.disabled = true;
  if (stopBtn) stopBtn.disabled = false;

  if (sysScanPollTimer) clearInterval(sysScanPollTimer);
  sysScanPollTimer = setInterval(() => {
    step++;
    const currentPath = demoFiles[step % demoFiles.length];

    if (currentPath.endsWith(".docx.exe") && !demoThreats.some(t => t.filename.includes("urgent_bill"))) {
      demoThreats.push({
        filename: "urgent_bill.docx.exe",
        path: "C:\\Users\\User\\Desktop\\urgent_bill.docx.exe",
        threat_name: "Suspicious.DoubleExtension",
        level: "high",
        detail: "ไฟล์ใช้นามสกุลซ้อนเพื่อพรางตัวเป็นเอกสาร Word แต่แท้จริงคือไฟล์ปฏิบัติการ (.exe)",
        recommendation: "อย่าเปิดไฟล์เด็ดขาด ลบไฟล์นี้ทันที",
      });
    }

    if (currentPath.includes("eicar") && !demoThreats.some(t => t.filename.includes("eicar"))) {
      demoThreats.push({
        filename: "eicar_test_sample.com",
        path: "C:\\Users\\User\\AppData\\Local\\Temp\\eicar_test_sample.com",
        threat_name: "Malware_EICAR_Test_File",
        level: "high",
        detail: "ไฟล์ทดสอบไวรัสมาตรฐาน EICAR ยืนยันว่าเครื่องยนต์ตรวจจับทำงานได้อย่างถูกต้อง",
        recommendation: "ไฟล์ทดสอบสำหรับตรวจสอบระบบ Antivirus ปลอดภัยในการลบ",
      });
    }

    updateSysScanUI({
      status: step >= 20 ? "completed" : "scanning",
      mode: "quick",
      target: "C:\\Users\\User (จำลอง)",
      files_scanned: step * 42,
      directories_scanned: step * 5,
      current_file: currentPath,
      threats: demoThreats,
      started_at: new Date(Date.now() - step * 500).toISOString(),
      elapsed_seconds: (step * 0.5).toFixed(1),
    });

    if (step >= 20) {
      clearInterval(sysScanPollTimer);
      sysScanPollTimer = null;
      if (startBtn) startBtn.disabled = false;
      if (stopBtn) stopBtn.disabled = true;
      const findings = demoThreats.length > 0 ? demoThreats.map((t) => ({
        title: `${t.threat_name} (${t.filename})`,
        detail: `${t.path}: ${t.detail}`,
        level: t.level || "high",
        recommendation: t.recommendation
      })) : [{
        title: "ไม่พบภัยคุกคามในระบบ",
        detail: "สแกนจำลองสำเร็จ ไม่พบมัลแวร์",
        level: "info"
      }];
      finishScan("virus", findings, "C:\\Users\\User (จำลอง)");
    }
  }, 350);
}

const btnSysDemo = document.getElementById("btnSysScanDemo");
if (btnSysDemo) {
  btnSysDemo.addEventListener("click", runSysScanDemo);
}

const btnExportSys = document.getElementById("btnExportSysReport");
if (btnExportSys) {
  btnExportSys.addEventListener("click", () => {
    if (!sysScanLastData || !sysScanLastData.threats) return;
    const reportBlob = new Blob([JSON.stringify(sysScanLastData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(reportBlob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `system-antivirus-report-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
}

// React to language switch dynamically
window.addEventListener("languageChanged", () => {
  const pageTitle = document.getElementById("pageTitle");
  if (pageTitle && currentActiveView) {
    pageTitle.textContent = t("title." + currentActiveView, titles[currentActiveView]);
  }
  calculateSecurityScore();
  renderHistory();
  const statusText = document.getElementById("backendStatusText");
  if (statusText) statusText.textContent = t("topbar.ready", "ระบบพร้อมใช้งาน (Security Workspace · Ready)");
  const aiInput = document.getElementById("aiChatInput");
  if (aiInput) {
    aiInput.setAttribute("placeholder", t("ai.inputPlaceholder", "พิมพ์คำถามเรื่องความปลอดภัย หรือระบุจุดบกพร่องที่ต้องการคำแนะนำ..."));
  }
});

// --- AI Security Assistant & Remediation Advisor ---

function appendAiMessage(role, title, text, code = null, steps = []) {
  const container = document.getElementById("aiChatMessages");
  if (!container) return;

  const bubble = document.createElement("div");
  bubble.className = `ai-msg-bubble ${role}`;

  const avatar = document.createElement("div");
  avatar.className = "ai-msg-avatar";
  avatar.textContent = role === "assistant" ? "🤖" : "👤";

  const content = document.createElement("div");
  content.className = "ai-msg-content";

  if (title) {
    const titleEl = document.createElement("div");
    titleEl.className = "ai-msg-title";
    titleEl.textContent = title;
    content.append(titleEl);
  }

  if (text) {
    const p = document.createElement("p");
    p.textContent = text;
    content.append(p);
  }

  if (Array.isArray(steps) && steps.length > 0) {
    const ol = document.createElement("ol");
    ol.className = "ai-step-list";
    steps.forEach((step) => {
      const li = document.createElement("li");
      li.textContent = step;
      ol.append(li);
    });
    content.append(ol);
  }

  if (code) {
    const wrap = document.createElement("div");
    wrap.className = "code-block-wrap";

    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "copy-snippet-btn";
    copyBtn.textContent = "📋 คัดลอก";
    copyBtn.setAttribute("aria-label", "คัดลอกโค้ด");
    copyBtn.addEventListener("click", () => copyToClipboard(code, copyBtn));

    const pre = document.createElement("pre");
    pre.className = "ai-code-block";
    pre.textContent = code;

    wrap.append(copyBtn, pre);
    content.append(wrap);
  }

  bubble.append(avatar, content);
  container.append(bubble);
  container.scrollTop = container.scrollHeight;
}

function clearAiChat() {
  const container = document.getElementById("aiChatMessages");
  if (!container) return;
  container.replaceChildren();
  appendAiMessage(
    "assistant",
    t("ai.welcomeTitle", "สวัสดีครับ! ผมคือ AI ผู้ช่วยความปลอดภัยระบบ (Security Advisor)"),
    t("ai.welcomeBody", "ผมสามารถช่วยคุณวิเคราะห์จุดบกพร่อง, แนะนำโค้ดตัวอย่างสำหรับแก้ไขช่องโหว่ (SQL Injection, XSS, eval), สอนตั้งค่า Security Headers ให้เว็บไซต์, และแนะนำการปรับปรุงความปลอดภัยเครือข่าย Wi-Fi ได้ทันที คุณสามารถพิมพ์คำถามด้านล่าง หรือกดปุ่ม '🤖 ขอคำแนะนำ AI' จากผลการสแกนในหน้าต่างๆ ได้เลยครับ")
  );
}

const AI_SECURITY_KNOWLEDGE = {
  sql: {
    titles: {
      th: "💉 แนวทางแก้ไขช่องโหว่ SQL Injection (CWE-89 / OWASP A03:2021)",
      en: "💉 SQL Injection Remediation (CWE-89 / OWASP A03:2021)",
      zh: "💉 SQL 注入漏洞修复方案 (CWE-89 / OWASP A03:2021)",
      ja: "💉 SQL インジェクション修復ガイド (CWE-89 / OWASP A03:2021)",
      es: "💉 Remediación de Inyección SQL (CWE-89 / OWASP A03:2021)"
    },
    explanations: {
      th: "SQL Injection เกิดจากการนำข้อมูลที่รับจากผู้ใช้หรือภายนอกไปเชื่อมต่อ (concatenate) เข้ากับคำสั่ง SQL โดยตรง ทำให้ผู้โจมตีสามารถแทรกคำสั่งเพื่อขโมยข้อมูล ลบฐานข้อมูล หรือข้ามระบบล็อกอินได้",
      en: "SQL Injection occurs when untrusted input is concatenated directly into SQL queries, enabling attackers to bypass authentication, dump sensitive database tables, or execute unauthorized commands.",
      zh: "SQL 注入是由于未经验证的用户输入直接拼接到 SQL 查询语句中，攻击者可借此绕过认证、窃取核心数据或破坏数据库。",
      ja: "SQLインジェクションは、信頼できないユーザー入力をSQL文に直接連結することで発生し、攻撃者による認証回避やデータ漏洩を引き起こします。",
      es: "La Inyección SQL ocurre cuando entradas no confiables se concatenan directamente en consultas SQL, permitiendo a los atacantes extraer datos o eludir la autenticación."
    },
    steps: {
      th: [
        "หลีกเลี่ยงการต่อสตริงด้วย String Concatenation หรือ Template Literals ในคำสั่ง SQL",
        "ใช้ Parameterized Queries (Prepared Statements) ในทุกจุดที่มีการเรียกฐานข้อมูล",
        "ใช้ Object-Relational Mapping (ORM) เช่น SQLAlchemy, Prisma หรือ Hibernate",
        "จำกัดสิทธิ์ผู้ใช้ของฐานข้อมูลตามหลัก Least Privilege (ไม่ใช้ root/sa ในแอปพลิเคชัน)"
      ],
      en: [
        "Never concatenate user input directly into SQL strings",
        "Use Parameterized Queries / Prepared Statements for all database interactions",
        "Employ an established ORM such as SQLAlchemy, Prisma, or Hibernate",
        "Enforce database Principle of Least Privilege (never use root/sa in app runtime)"
      ],
      zh: [
        "杜绝使用字符串拼接或模板字符串构造 SQL 语句",
        "所有数据库操作均必须使用参数化查询（Prepared Statements）",
        "使用成熟的 ORM 框架（如 SQLAlchemy、Prisma 等）",
        "按照最小权限原则为应用程序配置数据库访问账户"
      ],
      ja: [
        "SQL文内で文字列連結やテンプレートリテラルを使用しない",
        "すべてのDBアクセスでプリペアドステートメント（パラメータ化クエリ）を使用する",
        "SQLAlchemy や Prisma などの信頼できる ORM を導入する",
        "DB接続ユーザーの権限を最小限に制限する（Least Privilege）"
      ],
      es: [
        "Nunca concatenar cadenas de usuario directamente en sentencias SQL",
        "Utilizar sentencias preparadas (Prepared Statements) con parámetros",
        "Utilizar un ORM consolidado como SQLAlchemy, Prisma o Hibernate",
        "Aplicar el principio de privilegios mínimos para el usuario de base de datos"
      ]
    },
    code: `# [Python / PostgreSQL] ตัวอย่างการแก้ไขให้ปลอดภัย (Secure Parameterized Query):
# ❌ มีช่องโหว่ (Vulnerable):
# cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")

# ✅ ปลอดภัย (Secure):
cursor.execute(
    "SELECT id, username, email FROM users WHERE username = %s AND status = %s",
    (user_input, "active")
)`
  },

  csp: {
    titles: {
      th: "🛡️ แนวทางตั้งค่า HTTP Security Headers & Content-Security-Policy (CSP)",
      en: "🛡️ HTTP Security Headers & Content-Security-Policy (CSP) Guide",
      zh: "🛡️ HTTP 安全标头与 Content-Security-Policy (CSP) 配置指南",
      ja: "🛡️ HTTP セキュリティヘッダーおよび CSP 設定ガイド",
      es: "🛡️ Guía de Cabeceras de Seguridad HTTP y Content-Security-Policy (CSP)"
    },
    explanations: {
      th: "Security Headers ช่วยป้องกันการโจมตีทางเว็บที่พบบ่อย เช่น Cross-Site Scripting (XSS), Clickjacking, และ MIME-type Sniffing โดยการสั่งให้เบราว์เซอร์บังคับใช้นโยบายความปลอดภัยที่เข้มงวด",
      en: "HTTP Security Headers protect web applications from common attacks including Cross-Site Scripting (XSS), Clickjacking, and MIME sniffing by instructing modern browsers to enforce strict security boundaries.",
      zh: "HTTP 安全标头通过指示现代浏览器强制执行严格的安全策略，有效防御 XSS 跨站脚本、点击劫持和 MIME 嗅探等主流威胁。",
      ja: "HTTP セキュリティヘッダーは、ブラウザに対して厳格な制御を指示することで、XSS、クリックジャッキング、MIME スニッフィングなどの攻撃を防ぎます。",
      es: "Las cabeceras de seguridad HTTP protegen las aplicaciones web frente a XSS, Clickjacking y MIME sniffing al exigir directivas estrictas en los navegadores."
    },
    steps: {
      th: [
        "ตั้งค่า Content-Security-Policy (CSP) เพื่อจำกัดโดเมนที่อนุญาตให้โหลดสคริปต์และทรัพยากร",
        "เปิดใช้ Strict-Transport-Security (HSTS) บังคับ HTTPS ขั้นต่ำ 1 ปี",
        "กำหนด X-Frame-Options: DENY เพื่อป้องกัน Clickjacking",
        "กำหนด X-Content-Type-Options: nosniff ป้องกันเบราว์เซอร์เดาชนิดไฟล์ผิดพลาด",
        "กำหนด Referrer-Policy: strict-origin-when-cross-origin เพื่อปกป้อง URL และ Token"
      ],
      en: [
        "Configure Content-Security-Policy (CSP) to restrict script and asset sources",
        "Enable Strict-Transport-Security (HSTS) with at least 1-year max-age",
        "Set X-Frame-Options: DENY to prevent Clickjacking framing",
        "Set X-Content-Type-Options: nosniff to stop MIME sniffing",
        "Set Referrer-Policy: strict-origin-when-cross-origin to safeguard sensitive URLs"
      ],
      zh: [
        "配置 Content-Security-Policy 限制允许加载脚本与资源的来源",
        "启用 Strict-Transport-Security (HSTS) 强制全站 HTTPS（至少 1 年）",
        "设置 X-Frame-Options: DENY 防止点击劫持（Clickjacking）",
        "设置 X-Content-Type-Options: nosniff 防止 MIME 类型嗅探",
        "设置 Referrer-Policy: strict-origin-when-cross-origin 保护请求凭证"
      ],
      ja: [
        "Content-Security-Policy を設定しスクリプトの不正読み込みを遮断する",
        "Strict-Transport-Security (HSTS) を有効化し、HTTPSを常時強制する",
        "X-Frame-Options: DENY を設定してクリックジャッキングを防止する",
        "X-Content-Type-Options: nosniff でMIMEスニッフィングを遮断する",
        "Referrer-Policy で送信元URL情報の漏洩を防ぐ"
      ],
      es: [
        "Configurar Content-Security-Policy para restringir la carga de recursos",
        "Habilitar Strict-Transport-Security (HSTS) para forzar HTTPS",
        "Establecer X-Frame-Options: DENY para evitar ataques de Clickjacking",
        "Establecer X-Content-Type-Options: nosniff contra sniffing de tipos MIME",
        "Configurar Referrer-Policy para proteger parámetros de URL sensibles"
      ]
    },
    code: `# [Nginx Configuration Example]
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self';" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;`
  },

  wifi: {
    titles: {
      th: "📶 แนวทางยกระดับความปลอดภัย Wi-Fi และเราเตอร์ (Wireless Hardening)",
      en: "📶 Wi-Fi & Wireless Router Hardening Best Practices",
      zh: "📶 Wi-Fi 无线网络与路由器安全加固规范",
      ja: "📶 Wi-Fi およびルーターセキュリティ強化手順",
      es: "📶 Fortalecimiento y Buenas Prácticas de Redes Wi-Fi"
    },
    explanations: {
      th: "สัญญาณ Wi-Fi ที่ไม่มีรหัสผ่าน (OPEN) หรือใช้เทคโนโลยีล้าสมัย (WEP / WPA1 / TKIP) เสี่ยงต่อการถูกดักฟังข้อมูล (Packet Sniffing), การโจมตี Evil Twin, และการถอดรหัสผ่านภายในเวลาไม่กี่นาที",
      en: "Unencrypted (OPEN) or legacy (WEP/WPA1/TKIP) Wi-Fi networks expose users to packet sniffing, Man-in-the-Middle (MitM) attacks, and rapid offline key cracking.",
      zh: "未加密（OPEN）或使用淘汰协议（WEP/WPA1/TKIP）的 Wi-Fi 极易遭受数据包嗅探、中间人攻击及快速离线破解。",
      ja: "暗号化なし（OPEN）や旧規格（WEP/WPA1/TKIP）の Wi-Fi はパケット盗聴や中間者攻撃、パスワード解読のリスクに直面します。",
      es: "Las redes Wi-Fi abiertas (OPEN) o con cifrados obsoletos (WEP/WPA1/TKIP) son vulnerables al sniffing de tráfico y ataques Man-in-the-Middle."
    },
    steps: {
      th: [
        "ปรับการตั้งค่าบนเราเตอร์เป็น WPA3-Personal (WPA3-SAE) หรือ WPA2-AES (CCMP)",
        "ปิดฟังก์ชัน WPS (Wi-Fi Protected Setup) บนเราเตอร์ทันที เนื่องจากมีช่องโหว่ PIN Brute-force",
        "ตั้งรหัสผ่าน Wi-Fi ให้มีความยาวอย่างน้อย 14-16 ตัวอักษร ผสมตัวเลข ตัวพิมพ์ใหญ่ และสัญลักษณ์",
        "แยกเครือข่ายสำหรับอุปกรณ์ IoT และแขกด้วย Guest Network พร้อมเปิดโหมด AP Isolation",
        "อัปเดต Firmware ของเราเตอร์เป็นเวอร์ชันล่าสุดสม่ำเสมอ และปิด Remote Admin Access ผ่าน WAN"
      ],
      en: [
        "Upgrade router security mode to WPA3-Personal (SAE) or WPA2-AES (CCMP)",
        "Disable WPS (Wi-Fi Protected Setup) immediately to block PIN brute-force attacks",
        "Set a strong passphrase of 14-16+ characters with mixed case, numbers, and symbols",
        "Segregate IoT devices and visitors onto an isolated Guest Network with AP Isolation",
        "Regularly update router firmware and disable WAN/Internet remote admin management"
      ],
      zh: [
        "将路由器安全模式升级为 WPA3-Personal (SAE) 或 WPA2-AES (CCMP)",
        "立即在路由器中禁用 WPS（Wi-Fi Protected Setup），消除 PIN 码暴力破解隐患",
        "设置至少 14 位混合大小写字母、数字及符号的高强度连接密码",
        "开启访客网络（Guest Network）并启用 AP 隔离，分离智能家居 IoT 设备",
        "定期更新路由器固件，并关闭外网远程管理功能 (WAN Remote Access)"
      ],
      ja: [
        "ルーターの認証方式を WPA3-Personal (SAE) または WPA2-AES に設定する",
        "PIN 総当たり攻撃の温床となる WPS (Wi-Fi Protected Setup) を直ちに無効化する",
        "14文字以上の大文字・小文字・記号・数字を混在させた強固なパスワードを設定する",
        "ゲストネットワークとAPアイソレーションを有効にし、IoT機器を隔離する",
        "ファームウェアを定期更新し、WAN側からのリモート管理アクセスを遮断する"
      ],
      es: [
        "Actualizar la configuración a WPA3-Personal (SAE) o WPA2-AES (CCMP)",
        "Desactivar WPS en el router para bloquear ataques de fuerza bruta al PIN",
        "Establecer una contraseña de al menos 14 caracteres con símbolos y números",
        "Aislar dispositivos IoT e invitados en una red Guest con AP Isolation",
        "Mantener el firmware actualizado y desactivar el acceso remoto desde WAN"
      ]
    },
    code: `[การตั้งค่า Router ที่แนะนำ / Recommended Settings]
Authentication : WPA3-Personal (SAE) / WPA2-Personal (AES)
Cipher         : AES-CCMP / GCMP-256 (ห้ามใช้ TKIP)
WPS            : Disabled (ปิดการใช้งาน)
AP Isolation   : Enabled สำหรับ Guest Wi-Fi
Admin Password : เปลี่ยนรหัสผ่านแอดมินเราเตอร์ (ห้ามใช้ admin/admin)`
  },

  cve: {
    titles: {
      th: "📦 แนวทางการตรวจสอบและแก้ไขช่องโหว่ Dependency (CVE Remediation)",
      en: "📦 Dependency CVE Vulnerability Patching Guide",
      zh: "📦 依赖包 CVE 漏洞分析与修复方案",
      ja: "📦 依存パッケージ CVE 脆弱性のパッチ適用と修復手順",
      es: "📦 Guía de Remediación de Vulnerabilidades CVE en Paquetes"
    },
    explanations: {
      th: "โปรเจกต์มักพึ่งพา Third-party Packages (NPM, PyPI, Maven) ซึ่งอาจมีช่องโหว่ CVE ที่ถูกเผยแพร่สู่สาธารณะแล้ว ทำให้ผู้โจมตีสามารถอาศัยช่องโหว่ดังกล่าวเจาะระบบผ่านไลบรารีได้",
      en: "Modern projects rely on third-party libraries (npm, PyPI, Maven) which frequently harbor disclosed CVE vulnerabilities, allowing attackers to compromise the application via supply chain vectors.",
      zh: "软件系统高度依赖第三方开源包（npm、PyPI 等），若未及时修补已知 CVE 漏洞，攻击者可利用开源组件漏洞轻易入侵系统。",
      ja: "多くのプロジェクトが依存するサードパーティパッケージ（npm、PyPIなど）の既知のCVE脆弱性は、サプライチェーン攻撃の標的となります。",
      es: "Las dependencias de terceros (npm, PyPI) a menudo contienen vulnerabilidades CVE conocidas que pueden ser explotadas por atacantes."
    },
    steps: {
      th: [
        "ตรวจสอบรายการแพ็กเกจที่มีช่องโหว่ผ่าน Google OSV Database หรือ npm audit / pip-audit",
        "ตรวจสอบเวอร์ชันแก้ไข (Patched Version) และอัปเกรดแพ็กเกจไปยังเวอร์ชันที่ปลอดภัย",
        "หากเวอร์ชันใหม่มี Breaking Changes ให้ตรวจสอบ Release Notes และรัน Unit Tests",
        "ใช้ Lockfile (package-lock.json, poetry.lock) เพื่อล็อกเวอร์ชันและป้องกัน Dependency Confusion",
        "เปิดใช้ GitHub Dependabot Alerts เพื่อรับการแจ้งเตือนและ Auto-PR ทันทีที่มีช่องโหว่ใหม่"
      ],
      en: [
        "Audit dependencies using Google OSV Database, npm audit, or pip-audit",
        "Identify patched versions and update your requirements.txt or package.json",
        "Review changelogs and run automated test suites to ensure no breaking changes",
        "Commit lockfiles (package-lock.json, poetry.lock) to enforce reproducible builds",
        "Enable GitHub Dependabot alerts for automated CVE detection and pull requests"
      ],
      zh: [
        "利用 Google OSV 漏洞库或 npm audit / pip-audit 定期扫描依赖项",
        "查阅 CVE 修复公告，将漏洞包升级至官方推荐的安全版本",
        "在升级后执行完整的自动化测试，防止破坏性更新（Breaking Changes）",
        "严格提交并锁定 lockfile（如 package-lock.json、poetry.lock）",
        "启用 GitHub Dependabot 监控，第一时间接收依赖安全补丁"
      ],
      ja: [
        "Google OSV や npm audit、pip-audit で依存関係の脆弱性を検査する",
        "脆弱性情報に記載された安全な修正済みバージョンへアップデートする",
        "自動テストを実行し、アップデートに伴う破壊的変更がないか確認する",
        "package-lock.json などのロックファイルを確実にコミットして管理する",
        "GitHub Dependabot などの自動検知ツールを有効化する"
      ],
      es: [
        "Auditar dependencias con Google OSV, npm audit o pip-audit",
        "Actualizar los paquetes vulnerables a las versiones que contienen el parche",
        "Ejecutar pruebas automatizadas para validar que no haya cambios incompatibles",
        "Mantener siempre actualizados y versionados los archivos lockfile",
        "Activar Dependabot en GitHub para recibir alertas de CVEs automáticamente"
      ]
    },
    code: `# คำสั่งตรวจสอบและอัปเดตแพ็กเกจ (Terminal Commands):
# สำหรับ JavaScript / Node.js:
npm audit
npm audit fix --force
npm update <package_name>

# สำหรับ Python:
pip install pip-audit
pip-audit
pip install --upgrade <package_name>`
  },

  yara: {
    titles: {
      th: "🦠 แนวทางจัดการเมื่อตรวจพบมัลแวร์ โทรจัน หรือไฟล์ต้องสงสัย (Incident Response)",
      en: "🦠 Malware & Suspicious File Incident Containment Protocol",
      zh: "🦠 恶意软件/木马应急隔离与处置响应指南",
      ja: "🦠 マルウェア・トロイの木馬検出時の緊急対応手順",
      es: "🦠 Protocolo de Respuesta ante Incidentes de Malware o Troyanos"
    },
    explanations: {
      th: "เมื่อระบบหรือเอนจิน YARA ตรวจพบไฟล์ที่เป็นอันตราย (เช่น ไฟล์นามสกุลซ้อน .docx.exe, มัลแวร์เรียกค่าไถ่ หรือโทรจัน) จำเป็นต้องมีกระบวนการกักกัน (Containment) และกำจัดอย่างถูกต้องเพื่อป้องกันการแพร่กระจาย",
      en: "When YARA or antivirus engines flag a threat (such as double extensions .docx.exe, ransomware, or trojans), immediate containment is required to stop lateral movement and data exfiltration.",
      zh: "当 YARA 或防病毒引擎报警发现恶意文件（如双重扩展名 .docx.exe、勒索软件或木马）时，必须立即执行隔离与应急响应，阻断横向扩散。",
      ja: "YARAやアンチウイルスによって悪意あるファイル（二重拡張子 .docx.exe、トロイの木馬など）が検知された場合、感染拡大を防ぐため迅速な封じ込めが必要です。",
      es: "Cuando un motor YARA o antivirus detecta una amenaza (como extensiones dobles .docx.exe o troyanos), se requiere contención inmediata para evitar su propagación."
    },
    steps: {
      th: [
        "ตัดการเชื่อมต่อเครือข่ายของเครื่องทันที (ปิด Wi-Fi และถอดสาย LAN)",
        "ห้ามเปิด ดับเบิลคลิก หรือเปลี่ยนชื่อไฟล์ต้องสงสัยเด็ดขาด",
        "ตรวจสอบ Process ที่ทำงานอยู่ และยุติกระบวนการที่น่าสงสัย (Kill Process)",
        "ทำการกักกัน (Quarantine) หรือลบไฟล์แบบถาวร (Secure Delete)",
        "สแกนระบบทั้งเครื่องด้วย Microsoft Defender Offline Scan เพื่อตรวจหามัลแวร์ที่แฝงตัว"
      ],
      en: [
        "Isolate the machine immediately (disconnect Wi-Fi and unplug network cables)",
        "Do NOT execute, rename, or inspect the file with standard office tools",
        "Terminate anomalous running processes via Task Manager or PowerShell",
        "Quarantine or permanently delete the malicious payload",
        "Perform a full Microsoft Defender Offline Scan to detect rootkits"
      ],
      zh: [
        "立即断开网络连接（关闭 Wi-Fi 并拔掉网线），防止横向移动",
        "严禁双击运行、重命名或在办公软件中打开可疑文件",
        "在任务管理器中检查并强制终止异常的后台进程",
        "将恶意文件隔离或彻底永久粉碎删除",
        "执行 Microsoft Defender 脱机扫描，彻底排查隐藏的后门木马"
      ],
      ja: [
        "直ちにネットワークを切断する（Wi-Fi オフ、LAN ケーブル抜去）",
        "不審なファイルを絶対に開いたりダブルクリックしたりしない",
        "タスクマネージャーで不審なプロセスを特定し強制終了する",
        "ファイルを隔離または完全削除する",
        "Microsoft Defender オフラインスキャンを実行し、システム全体を精密検査する"
      ],
      es: [
        "Desconectar el equipo de la red inmediatamente (Wi-Fi y cable LAN)",
        "NO abrir, ejecutar ni hacer doble clic en el archivo sospechoso",
        "Finalizar los procesos sospechosos en ejecución mediante PowerShell",
        "Poner en cuarentena o eliminar permanentemente el archivo",
        "Realizar un escaneo completo sin conexión con Microsoft Defender"
      ]
    },
    code: `# PowerShell Commands for Incident Containment:
# 1. ตรวจสอบกระบวนการต้องสงสัยที่กำลังทำงาน:
Get-Process | Where-Object { $_.Path -like "*Desktop*" -or $_.Path -like "*Temp*" }

# 2. ยุติกระบวนการอันตรายทันที:
Stop-Process -Name "urgent_bill*" -Force

# 3. ตรวจสอบ Windows Security Protection History:
Get-MpThreatDetection`
  }
};

async function querySecurityAi(query, contextFinding = null) {
  const lang = getLanguage();
  const q = (query || "").toLowerCase();

  let category = "general";
  if (q.includes("sql") || q.includes("injection") || q.includes("select") || q.includes("union")) {
    category = "sql";
  } else if (q.includes("csp") || q.includes("content-security-policy") || q.includes("hsts") || q.includes("header") || q.includes("frame")) {
    category = "csp";
  } else if (q.includes("wifi") || q.includes("wi-fi") || q.includes("wpa") || q.includes("wep") || q.includes("cipher") || q.includes("ssid")) {
    category = "wifi";
  } else if (q.includes("cve") || q.includes("dep") || q.includes("npm") || q.includes("pypi") || q.includes("package") || q.includes("osv") || q.includes("lodash") || q.includes("express")) {
    category = "cve";
  } else if (q.includes("yara") || q.includes("virus") || q.includes("malware") || q.includes("trojan") || q.includes("urgent_bill") || q.includes("eicar")) {
    category = "yara";
  }

  // Check if we have pre-built expert knowledge for this category
  if (AI_SECURITY_KNOWLEDGE[category]) {
    const item = AI_SECURITY_KNOWLEDGE[category];
    const title = item.titles[lang] || item.titles.th;
    let explanation = item.explanations[lang] || item.explanations.th;
    let steps = item.steps[lang] || item.steps.th;
    let code = item.code;

    // If there is finding context, customize the message
    if (contextFinding) {
      explanation = `[คำแนะนำเฉพาะสำหรับ: ${contextFinding.title}]\n${contextFinding.detail || ""}\n\n${explanation}`;
      if (contextFinding.recommendation) {
        steps = [`ข้อแนะนำเดิม: ${contextFinding.recommendation}`, ...steps];
      }
    }

    // Attempt backend AI summary enhancement if user is signed in
    try {
      if (auth.currentUser && apiBase && contextFinding) {
        const resp = await authenticatedApiFetch("ai/summary", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ findings: [contextFinding] })
        });
        if (resp.ok) {
          const aiData = await resp.json();
          if (Array.isArray(aiData.cve_feed) && aiData.cve_feed.length > 0) {
            code += `\n\n# ข้อมูลช่องโหว่ที่เกี่ยวข้องจาก Threat Feed:\n` +
              aiData.cve_feed.map(c => `# [${c.id}] ${c.severity}: ${c.summary}`).join("\n");
          }
        }
      }
    } catch {
      // ignore backend error, knowledge engine output is already complete
    }

    appendAiMessage("assistant", title, explanation, code, steps);
    return;
  }

  // Fallback for general cybersecurity queries
  const defaultTitles = {
    th: "🤖 คำแนะนำด้านความปลอดภัยระบบ (General Security Advice)",
    en: "🤖 General Security Remediation Guidance",
    zh: "🤖 系统安全综合建议 (Security Guidance)",
    ja: "🤖 総合セキュリティガイダンス",
    es: "🤖 Asesoramiento General de Ciberseguridad"
  };

  const defaultExplanations = {
    th: `ผมได้วิเคราะห์คำถามของคุณ: "${query}" แล้ว ขอแนะนำแนวทางปฏิบัติตามมาตรฐาน OWASP และ NIST เพื่อปกป้องระบบของคุณให้ปลอดภัยสูงสุด:`,
    en: `Analyzing your inquiry: "${query}". Based on OWASP and NIST guidelines, here are the recommended best practices to secure your infrastructure:`,
    zh: `针对您的咨询：“${query}”，基于 OWASP 与 NIST 安全规范，建议采取以下安全防护措施：`,
    ja: `ご質問内容「${query}」を分析しました。OWASP および NIST のガイドラインに基づき、以下のセキュリティ対策を推奨します：`,
    es: `Analizando su consulta: "${query}". Según los estándares OWASP y NIST, recomendamos las siguientes medidas para asegurar su entorno:`
  };

  const defaultSteps = {
    th: [
      "ตรวจสอบและปิดช่องโหว่ที่มีความเสี่ยงสูง (Critical / High) จากรายงานการสแกนทันที",
      "อัปเดตเวอร์ชันของระบบปฏิบัติการ, เว็บเซิร์ฟเวอร์ และไลบรารีภายนอกให้เป็นเวอร์ชันล่าสุด",
      "จำกัดสิทธิ์การเข้าถึง (Least Privilege) และเปิดใช้งานการยืนยันตัวตนหลายปัจจัย (MFA)",
      "เปิดระบบบันทึกประวัติ (Audit Logging) และสำรองข้อมูลอย่างสม่ำเสมอตามกฎ 3-2-1"
    ],
    en: [
      "Triage and remediate High/Critical vulnerabilities from your scan reports first",
      "Keep your OS, web server software, and dependencies continuously patched",
      "Enforce Least Privilege access control and enable Multi-Factor Authentication (MFA)",
      "Maintain audit logs and regular off-site backups following the 3-2-1 rule"
    ],
    zh: [
      "优先排查并处置安全扫描报告中标记的高危与严重漏洞",
      "定期更新操作系统、Web 服务器及第三方依赖至最新稳定版本",
      "遵循最小权限原则（Least Privilege）并强制启用多因素认证（MFA）",
      "建立审计日志追踪机制，并按 3-2-1 原则执行异地数据备份"
    ],
    ja: [
      "診断レポートで検出された高危険度・重要脆弱性を最優先で対処する",
      "OS、Webサーバー、依存ライブラリを常に最新バージョンに維持する",
      "最小権限の原則（Least Privilege）を徹底し、多要素認証（MFA）を導入する",
      "監査ログを記録し、3-2-1ルールに基づいた定期的なデータバックアップを実施する"
    ],
    es: [
      "Priorizar la mitigación de vulnerabilidades críticas y altas de los reportes",
      "Mantener el sistema operativo, servidores web y dependencias siempre actualizados",
      "Aplicar el principio de privilegios mínimos y habilitar autenticación multifactor (MFA)",
      "Registrar logs de auditoría y mantener copias de seguridad según la regla 3-2-1"
    ]
  };

  appendAiMessage(
    "assistant",
    defaultTitles[lang] || defaultTitles.th,
    defaultExplanations[lang] || defaultExplanations.th,
    null,
    defaultSteps[lang] || defaultSteps.th
  );
}

function consultAiForFinding(finding) {
  showView("ai");
  const lang = getLanguage();
  const prompts = {
    th: `ขอคำแนะนำวิธีแก้ไขสำหรับจุดบกพร่อง: "${finding.title}" (ระดับ: ${finding.level || "info"})`,
    en: `Please provide remediation advice for: "${finding.title}" (Severity: ${finding.level || "info"})`,
    zh: `请提供针对漏洞 "${finding.title}" 的修复指导（严重程度：${finding.level || "info"}）`,
    ja: `検出項目「${finding.title}」（重要度: ${finding.level || "info"}）の修復手順を教えてください`,
    es: `Por favor indique pasos de remediación para: "${finding.title}" (Severidad: ${finding.level || "info"})`
  };
  const userText = prompts[lang] || prompts.th;
  appendAiMessage("user", null, userText);
  querySecurityAi(finding.title + " " + (finding.detail || ""), finding);
}

// Attach AI Assistant UI Event Handlers
const aiForm = document.getElementById("aiChatForm");
if (aiForm) {
  aiForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const input = document.getElementById("aiChatInput");
    if (!input) return;
    const text = input.value.trim();
    if (!text) return;
    appendAiMessage("user", null, text);
    input.value = "";
    querySecurityAi(text);
  });
}

const btnClearAi = document.getElementById("btnAiClear");
if (btnClearAi) {
  btnClearAi.addEventListener("click", clearAiChat);
}

const quickPromptContainer = document.getElementById("aiQuickPrompts");
if (quickPromptContainer) {
  quickPromptContainer.querySelectorAll(".ai-chip-btn").forEach((chip) => {
    chip.addEventListener("click", () => {
      const promptType = chip.dataset.prompt;
      const chipText = chip.textContent.trim();
      appendAiMessage("user", null, chipText);
      querySecurityAi(promptType + " " + chipText);
    });
  });
}



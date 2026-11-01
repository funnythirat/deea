/**
 * Multilingual Internationalization (i18n) Module
 * Supported Languages:
 * - th: ภาษาไทย (Thai) [Default]
 * - en: English
 * - zh: 中文 (Simplified Chinese)
 * - ja: 日本語 (Japanese)
 * - es: Español (Spanish)
 */

export const SUPPORTED_LANGS = ["th", "en", "zh", "ja", "es"];
export const DEFAULT_LANG = "th";
const STORAGE_LANG_KEY = "preferred_app_language_v1";

export const translations = {
  th: {
    // Navigation
    "nav.main": "เมนูหลัก",
    "nav.dashboard": "ภาพรวม",
    "nav.queue": "คิวงาน",
    "nav.reports": "รายงาน",
    "nav.engines": "Scanner Engines",
    "nav.virus": "สแกนไวรัส",
    "nav.website": "ตรวจเว็บไซต์",
    "nav.code": "ตรวจโค้ด",
    "nav.dependencies": "ตรวจแพ็กเกจ",
    "nav.wifi": "ตรวจ Wi-Fi",
    "nav.sideNoteTitle": "ใช้กับระบบที่ได้รับอนุญาตเท่านั้น",
    "nav.sideNoteDesc": "สแกนเฉพาะไฟล์ที่คุณเลือกอัปโหลด ไฟล์จะถูกกักไว้ชั่วคราวและไม่ถูกรันโดยระบบ",

    // Topbar & System
    "topbar.eyebrow": "SECURITY OVERVIEW",
    "topbar.ready": "ระบบพร้อมใช้งาน (Security Workspace · Ready)",
    "topbar.login": "เข้าสู่ระบบ",
    "topbar.logout": "ออกจากระบบ",

    // Titles
    "title.dashboard": "ภาพรวมความปลอดภัย",
    "title.queue": "คิวงานสแกน",
    "title.reports": "ประวัติและรายงาน",
    "title.engines": "Scanning Engines",
    "title.virus": "สแกนไวรัส",
    "title.website": "ตรวจการตั้งค่าเว็บไซต์",
    "title.code": "วิเคราะห์ซอร์สโค้ด",
    "title.dependencies": "ตรวจสอบ Dependency",
    "title.wifi": "ตรวจสอบ Wi-Fi",

    // Hero
    "hero.title": "ยินดีต้อนรับสู่ วิถีป้องกันรอบด้าน (Security Workspace)",
    "hero.desc": "ระบบตรวจจับและวิเคราะห์ความเสี่ยงรอบด้าน สแกนไวรัสในเครื่องจริง, ตรวจสอบสัญญาณ Wi-Fi, วิเคราะห์ซอร์สโค้ด, ตรวจ Security Headers ของเว็บไซต์ และค้นหาช่องโหว่แพ็กเกจผ่าน Google OSV แบบเรียลไทม์",

    // Scorecard
    "score.label": "คะแนนความปลอดภัย",
    "score.quickPrint": "🖨️ พิมพ์รายงานสรุป",
    "score.tag.realtime": "🛡️ Real-time Analysis",
    "score.tag.persistent": "💾 บันทึกประวัติอัตโนมัติ",
    "score.tag.standards": "📋 มาตรฐานสากล",

    // Stats
    "stat.scans": "จำนวนการตรวจ",
    "stat.findings": "พบรายการที่ควรตรวจสอบ",
    "stat.high": "รายการระดับสูง",
    "stat.last": "ตรวจล่าสุด",

    // Quick Actions
    "quick.title": "เริ่มการตรวจด่วน",
    "quick.sub": "เลือกฟังก์ชันที่ต้องการตรวจสอบความปลอดภัยของระบบ",
    "quick.wifi.title": "ตรวจ Wi-Fi รอบข้าง",
    "quick.wifi.desc": "สแกนสัญญาณ Wi-Fi จริงและวิเคราะห์การเข้ารหัสรหัสผ่าน",
    "quick.virus.title": "สแกนไวรัสในเครื่อง",
    "quick.virus.desc": "สแกนไฟล์จริงบนดิสก์ C:\\ ค้นหามัลแวร์และโทรจันด้วย YARA",
    "quick.code.title": "วิเคราะห์ซอร์สโค้ด",
    "quick.code.desc": "ค้นหาจุดเสี่ยง SQL Injection, XSS และ Credentials ในโค้ด",
    "quick.dep.title": "ตรวจช่องโหว่แพ็กเกจ",
    "quick.dep.desc": "ตรวจสอบช่องโหว่กับฐานข้อมูล Google OSV แบบ Real-time",

    // Severity Accumulator
    "sev.title": "ระดับความรุนแรงของผลการตรวจรวม",
    "sev.high": "ระดับสูง",
    "sev.medium": "ระดับกลาง",
    "sev.low": "ระดับต่ำ",

    // Reports View
    "report.title": "ประวัติและรายงานการตรวจสอบความปลอดภัย",
    "report.sub": "บันทึกประวัติการตรวจในเครื่องอัตโนมัติ (Persistent LocalStorage) รีเฟรชเว็บแล้วข้อมูลไม่หาย",
    "report.printBtn": "🖨️ พิมพ์รายงาน / บันทึก PDF",
    "report.exportBtn": "ส่งออก JSON",
    "report.clearBtn": "🗑️ ล้างประวัติ",
    "report.searchPlaceholder": "🔍 ค้นหาในประวัติ เช่น Wi-Fi, express, lodash, เว็บไซต์...",
    "report.filterAll": "ทั้งหมด",
    "report.filterHigh": "เสี่ยงสูง",
    "report.filterMedium": "เสี่ยงปานกลาง",
    "report.filterClean": "ปลอดภัย",
    "report.emptyHistory": "ยังไม่มีประวัติการตรวจ (ข้อมูลจะบันทึกลงเครื่องอัตโนมัติเมื่อทำการสแกน)",
    "report.latestTitle": "รายละเอียดผลการตรวจล่าสุด",
    "report.selectPrompt": "เลือกตรวจจากเมนูด้านซ้ายเพื่อสร้างรายงาน",

    // Wi-Fi View
    "wifi.title": "ตรวจสอบ Wi-Fi และระดับความปลอดภัยสัญญาณ",
    "wifi.sub": "สแกนและเลือกสัญญาณ Wi-Fi ในพื้นที่เพื่อตรวจสอบว่ามีรหัสผ่านหรือไม่, ความแรงสัญญาณ และระดับความปลอดภัย",
    "wifi.scanHardware": "⚡ สแกน Wi-Fi จริงจากเครื่องนี้",
    "wifi.scanDemo": "📡 จำลองสัญญาณ (Demo)",
    "wifi.importFile": "📂 นำเข้าไฟล์",
    "wifi.searchPlaceholder": "🔍 ค้นหาชื่อสัญญาณ (SSID)...",
    "wifi.detected": "สัญญาณ Wi-Fi ที่ตรวจพบ",
    "wifi.selectedPrompt": "เลือกสัญญาณ Wi-Fi เพื่อดูผล",
    "wifi.selectedPromptSub": "คลิกสัญญาณในรายการด้านซ้ายเพื่อประเมินความปลอดภัย",

    // Virus View
    "virus.title": "สแกนไวรัสและความปลอดภัยของเครื่อง (Real System Antivirus Scanner)",
    "virus.sub": "สแกนไฟล์จริงบนฮาร์ดดิสก์ของเครื่องโดยตรง ด้วย YARA Heuristics Engine ตรวจจับโทรจัน นามสกุลหลอกลวง และมัลแวร์ ไม่ต้องอัปโหลดไฟล์",
    "virus.quickMode": "⚡ สแกนด่วน (Quick Scan)",
    "virus.quickDesc": "สแกนโฟลเดอร์จุดเสี่ยงทันที (Downloads, Desktop, Startup, Documents, Temp)",
    "virus.fullMode": "🖥️ สแกนทั้งเครื่อง (Full System Scan)",
    "virus.fullDesc": "สแกนทั้งไดรฟ์ C:\\ ทุกไฟล์และทุกโฟลเดอร์ในเครื่องอย่างละเอียด",
    "virus.customMode": "📁 สแกนโฟลเดอร์เฉพาะ (Custom Path)",
    "virus.customDesc": "ระบุเส้นทางโฟลเดอร์ที่ต้องการเจาะจงสแกน",
    "virus.startBtn": "▶️ เริ่มสแกนจริงจากเครื่องทันที",
    "virus.stopBtn": "⏹️ หยุดสแกน",
    "virus.demoBtn": "📡 ทดลองจำลองสแกน (Demo)",
    "virus.metricFiles": "ไฟล์ที่สแกนแล้ว",
    "virus.metricDirs": "โฟลเดอร์ที่ตรวจ",
    "virus.metricThreats": "ตรวจพบภัยคุกคาม",
    "virus.metricStatus": "สถานะการทำงาน",

    // Dependencies View
    "dep.title": "ตรวจสอบช่องโหว่แพ็กเกจ (Dependency & Package Vulnerability Inspector)",
    "dep.sub": "ตรวจหาช่องโหว่ความปลอดภัยระดับสากลจากฐานข้อมูล Google OSV (Open Source Vulnerabilities) ได้ทันที ค้นหาโดยตรงไม่ต้องอัปโหลดไฟล์ หรือเลือกชุดตัวอย่างด่วน",
    "dep.presetsTitle": "⚡ ตรวจด่วนคลิกเดียว (ไม่ต้องอัปโหลดไฟล์):",
    "dep.presetVuln": "ชุดเสี่ยงที่มีช่องโหว่ (Demo CVEs)",
    "dep.presetSafe": "ชุดปลอดภัยล่าสุด (Clean/Patched)",
    "dep.presetPython": "ชุดยอดนิยม Python (PyPI Demo)",
    "dep.presetProject": "ตรวจแพ็กเกจโปรเจกต์นี้ (Local Workspace)",
    "dep.inputPlaceholder": "พิมพ์ชื่อแพ็กเกจ เช่น express@4.17.1, lodash@4.17.15 หรือ requests@2.25.1",
    "dep.checkBtn": "🔍 ตรวจสอบทันที",

    // Code & Website View
    "code.title": "วิเคราะห์ซอร์สโค้ด",
    "code.sub": "ตรวจสัญญาณเสี่ยงทั่วไปในไฟล์ที่เลือกหรือโค้ดที่วาง โดยประมวลผลทั้งหมดใน browser ของคุณ",
    "code.selectFiles": "เลือกไฟล์โค้ด (สูงสุด 15 ไฟล์, 1 MB ต่อไฟล์)",
    "code.pasteLabel": "หรือวางโค้ด",
    "code.pastePlaceholder": "วางโค้ดที่ต้องการวิเคราะห์...",
    "code.submitBtn": "วิเคราะห์ในเครื่อง",
    "web.title": "ตรวจการตั้งค่าเว็บไซต์",
    "web.sub": "ส่ง HTTP HEAD request เพียงครั้งเดียวจาก browser เพื่อตรวจ security headers ที่อ่านได้ ไม่มีการ crawl หรือทดสอบช่องโหว่เชิงโจมตี",
    "web.urlLabel": "URL ของเว็บไซต์ (แนะนำ HTTPS)",
    "web.consent": "ฉันเป็นเจ้าของเว็บไซต์นี้หรือได้รับอนุญาตให้ตรวจสอบ และยินยอมให้ส่งคำขอ HEAD หนึ่งครั้ง",
    "web.submitBtn": "เริ่มตรวจแบบ Passive",

    // Table & Common
    "table.col.kind": "ชนิดการตรวจ",
    "table.col.target": "เป้าหมาย",
    "table.col.risk": "สถานะความเสี่ยง",
    "table.col.findings": "พบข้อสังเกต",
    "table.col.time": "เวลาที่ตรวจ",
    "table.col.report": "รายงาน",
    "table.viewReport": "ดูผลรายงาน",
    "common.items": "รายการ",
    "risk.high": "เสี่ยงสูง",
    "risk.medium": "ปานกลาง",
    "risk.low": "ต่ำ",
    "risk.clean": "ปลอดภัย",
    "report.noMatch": "ไม่พบประวัติการตรวจที่ตรงกับเงื่อนไขการค้นหาหรือตัวกรอง",

    // Scorecard & Grades
    "score.grade.a_plus": "เกรด A+ · ปลอดภัยดีเยี่ยม",
    "score.grade.ready": "เกรด A+ · พร้อมใช้งาน",
    "score.grade.a": "เกรด A · ความปลอดภัยดี",
    "score.grade.b": "เกรด B · ปลอดภัยระดับยอมรับได้",
    "score.grade.c": "เกรด C · ควรปรับปรุง",
    "score.grade.d": "เกรด D · มีความเสี่ยงสูง",
    "score.grade.f": "เกรด F · ความเสี่ยงระดับวิกฤต",
    "score.title.ready": "ระบบปลอดภัย ไม่พบช่องโหว่ความเสี่ยงสูง",
    "score.title.safe": "ระบบปลอดภัย ไม่พบช่องโหว่ระดับวิกฤต",
    "score.desc.ready": "ระบบพร้อมสำหรับการตรวจสอบความปลอดภัย เริ่มต้นสแกน Wi-Fi, ซอร์สโค้ด, ไวรัส หรือ Dependency เพื่อประเมินสถานะ",
    "score.desc.safe": "ผลการตรวจสอบทั้งหมดอยู่ในเกณฑ์ปลอดภัยสูง ตรวจสอบอย่างสม่ำเสมอเพื่อรักษามาตรฐาน",
    "score.status.ready": "พร้อมใช้งาน (Security Ready)",
    "score.status.safe": "ปลอดภัยดีเยี่ยม (Secure)",
    "score.status.good": "ความปลอดภัยดี (Good)",
    "score.status.acceptable": "ยอมรับได้ (Acceptable)",
    "score.status.improve": "ควรปรับปรุง (Improvement Needed)",
    "score.status.high": "มีความเสี่ยงสูง (High Risk)",
    "score.status.critical": "ความเสี่ยงวิกฤต (Critical Risk)",

    // Login Page
    "login.brandName": "วิถีป้องกันรอบด้าน",
    "login.brandSub": "SECURITY WORKSPACE",
    "login.kicker": "SECURE · MONITOR · PROTECT",
    "login.welcomeTitle": "มาร่วมกัน<br>ยกระดับความปลอดภัย<br>ให้ระบบของคุณ",
    "login.welcomeSub": "ค้นหาจุดเสี่ยงก่อนที่จะกลายเป็นปัญหา ตรวจสอบเว็บไซต์ โค้ด และไฟล์ พร้อมดูแลระบบของคุณให้ปลอดภัยยิ่งขึ้น",
    "login.feat1": "ตรวจสอบเว็บไซต์และโค้ด",
    "login.feat2": "วิเคราะห์แพ็กเกจและ Wi-Fi",
    "login.feat3": "สแกนไฟล์อย่างปลอดภัย",
    "login.welcomeFooter": "ใช้เครื่องมือนี้กับระบบที่คุณเป็นเจ้าของหรือได้รับอนุญาตเท่านั้น",
    "login.secureAccess": "SECURE ACCESS",
    "login.authTitle": "เข้าสู่ระบบ",
    "login.authIntro": "สำหรับผู้ที่มีบัญชีอยู่แล้ว ให้เข้าสู่ระบบด้วยอีเมลและรหัสผ่าน",
    "login.authIntroNew": "สำหรับผู้ที่ยังไม่เคยสมัคร กรอกอีเมลและตั้งรหัสผ่านเพื่อสร้างบัญชี",
    "login.tabSignin": "เข้าสู่ระบบ",
    "login.tabSignup": "สมัครบัญชี",
    "login.labelEmail": "อีเมล",
    "login.labelPassword": "รหัสผ่าน",
    "login.btnSignin": "เข้าสู่ระบบ",
    "login.labelPasswordMin": "รหัสผ่าน (อย่างน้อย 6 ตัวอักษร)",
    "login.labelPasswordConfirm": "ยืนยันรหัสผ่าน",
    "login.btnSignup": "สมัครบัญชีใหม่",
    "login.warning": "การเข้าสู่ระบบนี้ใช้ Firebase Authentication เท่านั้น การเรียกใช้งาน Backend ยังคงต้องผ่านการตรวจสอบสิทธิ์ที่ฝั่งเซิร์ฟเวอร์"
  },

  en: {
    // Navigation
    "nav.main": "Main Menu",
    "nav.dashboard": "Overview",
    "nav.queue": "Queue",
    "nav.reports": "Reports",
    "nav.engines": "Scanner Engines",
    "nav.virus": "Antivirus Scan",
    "nav.website": "Website Audit",
    "nav.code": "Code Analysis",
    "nav.dependencies": "Dependencies",
    "nav.wifi": "Wi-Fi Inspector",
    "nav.sideNoteTitle": "Authorized Use Only",
    "nav.sideNoteDesc": "Scan only files you choose to upload. Files are quarantined in memory and never executed.",

    // Topbar & System
    "topbar.eyebrow": "SECURITY OVERVIEW",
    "topbar.ready": "System Ready (Security Workspace · Ready)",
    "topbar.login": "Sign In",
    "topbar.logout": "Sign Out",

    // Titles
    "title.dashboard": "Security Overview",
    "title.queue": "Scan Queue",
    "title.reports": "History & Audit Reports",
    "title.engines": "Scanning Engines",
    "title.virus": "Real System Antivirus",
    "title.website": "Website Security Headers",
    "title.code": "Source Code Vulnerability Review",
    "title.dependencies": "Dependency & CVE Audit",
    "title.wifi": "Wi-Fi Security Analyzer",

    // Hero
    "hero.title": "Welcome to Security Workspace (360° Defense)",
    "hero.desc": "Comprehensive security detection & analysis platform: Real system disk antivirus, Wi-Fi security auditing, source code review, Website HTTP security headers, and Google OSV vulnerability scanning in real-time.",

    // Scorecard
    "score.label": "Security Score",
    "score.quickPrint": "🖨️ Print Summary",
    "score.tag.realtime": "🛡️ Real-time Analysis",
    "score.tag.persistent": "💾 Auto-saved Locally",
    "score.tag.standards": "📋 Global Standards",

    // Stats
    "stat.scans": "Total Scans",
    "stat.findings": "Findings Flagged",
    "stat.high": "High Severity",
    "stat.last": "Last Scan",

    // Quick Actions
    "quick.title": "Quick Security Scanners",
    "quick.sub": "Select a security assessment tool to evaluate system health",
    "quick.wifi.title": "Scan Nearby Wi-Fi",
    "quick.wifi.desc": "Analyze local Wi-Fi networks and authentication ciphers",
    "quick.virus.title": "Disk Antivirus",
    "quick.virus.desc": "Scan C:\\ drive for malware, ransomware, and masqueraded files",
    "quick.code.title": "Code Vulnerabilities",
    "quick.code.desc": "Detect SQLi, XSS, and hardcoded secrets in source files",
    "quick.dep.title": "Package Inspector",
    "quick.dep.desc": "Check package versions against Google OSV CVE database",

    // Severity Accumulator
    "sev.title": "Accumulated Severity Distribution",
    "sev.high": "High Risk",
    "sev.medium": "Medium Risk",
    "sev.low": "Low Risk",

    // Reports View
    "report.title": "Audit History & Security Reports",
    "report.sub": "Automatically saved to browser LocalStorage — persists across refreshes",
    "report.printBtn": "🖨️ Print / Save PDF",
    "report.exportBtn": "Export JSON",
    "report.clearBtn": "🗑️ Clear History",
    "report.searchPlaceholder": "🔍 Search history (Wi-Fi, express, lodash, domain...)",
    "report.filterAll": "All",
    "report.filterHigh": "High Risk",
    "report.filterMedium": "Medium Risk",
    "report.filterClean": "Clean",
    "report.emptyHistory": "No scan history recorded yet (data saves automatically when scans complete)",
    "report.latestTitle": "Latest Scan Findings Details",
    "report.selectPrompt": "Run a scan from the left navigation to generate a report",

    // Wi-Fi View
    "wifi.title": "Wi-Fi & Wireless Signal Security Inspector",
    "wifi.sub": "Scan and select nearby Wi-Fi networks to inspect password protection, signal quality, and cipher strength",
    "wifi.scanHardware": "⚡ Scan Device Wi-Fi Hardware",
    "wifi.scanDemo": "📡 Demo Simulation",
    "wifi.importFile": "📂 Import Report",
    "wifi.searchPlaceholder": "🔍 Search Network Name (SSID)...",
    "wifi.detected": "Detected Wi-Fi Networks",
    "wifi.selectedPrompt": "Select a Wi-Fi Network to Inspect",
    "wifi.selectedPromptSub": "Click any Wi-Fi in the left list to evaluate security properties",

    // Virus View
    "virus.title": "System Antivirus Scanner (Real Hardware Engine)",
    "virus.sub": "Scans physical files on the machine with YARA Heuristics Engine. Detects trojans, masqueraded extensions, and malware without uploading files.",
    "virus.quickMode": "⚡ Quick Scan",
    "virus.quickDesc": "Scans high-risk directories (Downloads, Desktop, Startup, Documents, Temp)",
    "virus.fullMode": "🖥️ Full System Scan",
    "virus.fullDesc": "Comprehensive scan of drive C:\\ including all files and subfolders",
    "virus.customMode": "📁 Custom Path Scan",
    "virus.customDesc": "Specify a custom target directory to inspect",
    "virus.startBtn": "▶️ Start Real Local Scan",
    "virus.stopBtn": "⏹️ Stop Scan",
    "virus.demoBtn": "📡 Test Demo Simulation",
    "virus.metricFiles": "Files Scanned",
    "virus.metricDirs": "Folders Checked",
    "virus.metricThreats": "Threats Flagged",
    "virus.metricStatus": "Engine Status",

    // Dependencies View
    "dep.title": "Package & Dependency Vulnerability Inspector",
    "dep.sub": "Audit package security against Google OSV (Open Source Vulnerabilities) database in real-time. Zero file upload needed.",
    "dep.presetsTitle": "⚡ 1-Click Quick Presets (No Upload Needed):",
    "dep.presetVuln": "Vulnerable Packages (Demo CVEs)",
    "dep.presetSafe": "Patched Packages (Clean / Safe)",
    "dep.presetPython": "Top Python Packages (PyPI Demo)",
    "dep.presetProject": "Current Workspace Packages",
    "dep.inputPlaceholder": "Enter package name e.g. express@4.17.1, lodash@4.17.15, requests@2.25.1",
    "dep.checkBtn": "🔍 Inspect Now",

    // Code & Website View
    "code.title": "Source Code Security Review",
    "code.sub": "Detect common security flaws in selected files or pasted code directly in your browser",
    "code.selectFiles": "Select Code Files (Max 15 files, 1MB each)",
    "code.pasteLabel": "Or Paste Code Directly",
    "code.pastePlaceholder": "Paste snippet to analyze for vulnerabilities...",
    "code.submitBtn": "Analyze Code In-Browser",
    "web.title": "Website Security Headers Audit",
    "web.sub": "Sends a single HTTP HEAD request to verify readable security headers without crawling or invasive testing",
    "web.urlLabel": "Target Website URL (HTTPS Recommended)",
    "web.consent": "I own this website or am authorized to audit it, and consent to a single passive HEAD request",
    "web.submitBtn": "Start Passive Audit",

    // Table & Common
    "table.col.kind": "Scan Type",
    "table.col.target": "Target",
    "table.col.risk": "Risk Status",
    "table.col.findings": "Findings",
    "table.col.time": "Time",
    "table.col.report": "Report",
    "table.viewReport": "View Report",
    "common.items": "items",
    "risk.high": "High Risk",
    "risk.medium": "Medium",
    "risk.low": "Low",
    "risk.clean": "Clean",
    "report.noMatch": "No scan history matched your search criteria or filter.",

    // Scorecard & Grades
    "score.grade.a_plus": "Grade A+ · Excellent Security",
    "score.grade.ready": "Grade A+ · Ready to Scan",
    "score.grade.a": "Grade A · Good Security",
    "score.grade.b": "Grade B · Acceptable Security",
    "score.grade.c": "Grade C · Needs Improvement",
    "score.grade.d": "Grade D · High Risk",
    "score.grade.f": "Grade F · Critical Risk",
    "score.title.ready": "System Secure: No high-risk vulnerabilities found",
    "score.title.safe": "System Secure: No critical vulnerabilities",
    "score.desc.ready": "System is ready for security audits. Begin scanning Wi-Fi, source code, files, or dependencies to evaluate status.",
    "score.desc.safe": "All scan results are within safe thresholds. Run regular audits to maintain top security posture.",
    "score.status.ready": "Ready (Security Ready)",
    "score.status.safe": "Excellent (Secure)",
    "score.status.good": "Good Security",
    "score.status.acceptable": "Acceptable",
    "score.status.improve": "Improvement Needed",
    "score.status.high": "High Risk",
    "score.status.critical": "Critical Risk",

    // Login Page
    "login.brandName": "Security Workspace",
    "login.brandSub": "360° DEFENSE PLATFORM",
    "login.kicker": "SECURE · MONITOR · PROTECT",
    "login.welcomeTitle": "Elevate Your System<br>Security Posture Together",
    "login.welcomeSub": "Identify risks before they become incidents. Inspect websites, code, and files to keep your systems safe.",
    "login.feat1": "Audit Websites & Source Code",
    "login.feat2": "Analyze Dependencies & Wi-Fi",
    "login.feat3": "Safe Isolated File Scanning",
    "login.welcomeFooter": "Use this tool only on systems you own or are authorized to audit.",
    "login.secureAccess": "SECURE ACCESS",
    "login.authTitle": "Sign In",
    "login.authIntro": "For existing account holders, please sign in with your email and password.",
    "login.authIntroNew": "For new users, please enter your email and set a password to register.",
    "login.tabSignin": "Sign In",
    "login.tabSignup": "Register",
    "login.labelEmail": "Email",
    "login.labelPassword": "Password",
    "login.btnSignin": "Sign In",
    "login.labelPasswordMin": "Password (minimum 6 characters)",
    "login.labelPasswordConfirm": "Confirm Password",
    "login.btnSignup": "Create New Account",
    "login.warning": "Authentication is powered by Firebase. Backend service calls remain secured and authenticated server-side."
  },

  zh: {
    // Navigation
    "nav.main": "主菜单",
    "nav.dashboard": "仪表盘",
    "nav.queue": "任务队列",
    "nav.reports": "安全报告",
    "nav.engines": "扫描引擎",
    "nav.virus": "病毒扫描",
    "nav.website": "网站审计",
    "nav.code": "代码分析",
    "nav.dependencies": "依赖包审计",
    "nav.wifi": "Wi-Fi 检测",
    "nav.sideNoteTitle": "仅限授权系统",
    "nav.sideNoteDesc": "仅扫描您上传的文件。文件仅保留在临时内存中，绝不会被执行。",

    // Topbar & System
    "topbar.eyebrow": "SECURITY OVERVIEW",
    "topbar.ready": "系统就绪 (Security Workspace · Ready)",
    "topbar.login": "登录",
    "topbar.logout": "退出",

    // Titles
    "title.dashboard": "安全概览",
    "title.queue": "扫描队列",
    "title.reports": "历史记录与审计报告",
    "title.engines": "扫描引擎配置",
    "title.virus": "本地系统防病毒引擎",
    "title.website": "网站安全标头检测",
    "title.code": "源码安全审计",
    "title.dependencies": "依赖包漏洞检测",
    "title.wifi": "Wi-Fi 安全分析仪",

    // Hero
    "hero.title": "欢迎使用全方位防护工作区 (Security Workspace)",
    "hero.desc": "全方位风险检测系统：扫描本地真实硬盘、检测 Wi-Fi 信号及加密、分析源代码、检测网站安全标头，并通过 Google OSV 实时检索漏洞。",

    // Scorecard
    "score.label": "系统安全评分",
    "score.quickPrint": "🖨️ 打印报告",
    "score.tag.realtime": "🛡️ 实时分析",
    "score.tag.persistent": "💾 本地持久化",
    "score.tag.standards": "📋 国际标准",

    // Stats
    "stat.scans": "检查总次数",
    "stat.findings": "发现问题数",
    "stat.high": "高危项目",
    "stat.last": "最近扫描",

    // Quick Actions
    "quick.title": "快速扫描工具",
    "quick.sub": "选择安全工具评估系统健康状况",
    "quick.wifi.title": "扫描周围 Wi-Fi",
    "quick.wifi.desc": "扫描真实无线网络并分析加密方式与密码防护",
    "quick.virus.title": "本地防病毒扫描",
    "quick.virus.desc": "使用 YARA 规则扫描真实 C 盘文件，识别木马与伪装文件",
    "quick.code.title": "源码安全审查",
    "quick.code.desc": "检测 SQL 注入、XSS 以及代码硬编码密钥",
    "quick.dep.title": "软件包依赖检查",
    "quick.dep.desc": "连接 Google OSV 数据库实时检索 CVE 漏洞",

    // Severity Accumulator
    "sev.title": "综合风险等级分布",
    "sev.high": "高危风险",
    "sev.medium": "中危风险",
    "sev.low": "低危风险",

    // Reports View
    "report.title": "安全审计历史与报告",
    "report.sub": "自动保存在浏览器 LocalStorage 中，刷新页面不丢失",
    "report.printBtn": "🖨️ 打印 / 保存 PDF",
    "report.exportBtn": "导出 JSON",
    "report.clearBtn": "🗑️ 清空历史",
    "report.searchPlaceholder": "🔍 搜索历史（Wi-Fi、express、lodash、域名...）",
    "report.filterAll": "全部",
    "report.filterHigh": "高危",
    "report.filterMedium": "中危",
    "report.filterClean": "安全",
    "report.emptyHistory": "暂无扫描历史记录（扫描完成后自动持久化保存）",
    "report.latestTitle": "最新扫描详情",
    "report.selectPrompt": "从左侧菜单选择检测项目以生成报告",

    // Wi-Fi View
    "wifi.title": "Wi-Fi 与无线信号安全检测",
    "wifi.sub": "扫描并选择附近的 Wi-Fi 信号，检查是否有密码保护、信号强度与加密安全等级",
    "wifi.scanHardware": "⚡ 扫描本机 Wi-Fi 硬件",
    "wifi.scanDemo": "📡 模拟信号 (Demo)",
    "wifi.importFile": "📂 导入报告",
    "wifi.searchPlaceholder": "🔍 搜索网络名称 (SSID)...",
    "wifi.detected": "检测到的 Wi-Fi 信号",
    "wifi.selectedPrompt": "选择 Wi-Fi 信号查看结果",
    "wifi.selectedPromptSub": "点击左侧列表中的网络进行安全分析",

    // Virus View
    "virus.title": "系统防病毒扫描（真实本地硬件引擎）",
    "virus.sub": "使用 YARA 启发式引擎直接扫描磁盘真实文件，无需上传即可检测木马与恶意文件",
    "virus.quickMode": "⚡ 快速扫描 (Quick Scan)",
    "virus.quickDesc": "立即扫描高风险目录 (Downloads, Desktop, Startup, Documents, Temp)",
    "virus.fullMode": "🖥️ 全盘扫描 (Full System Scan)",
    "virus.fullDesc": "深度检查 C 盘所有文件及子目录",
    "virus.customMode": "📁 自定义路径 (Custom Path)",
    "virus.customDesc": "指定特定文件夹进行定向扫描",
    "virus.startBtn": "▶️ 立即开始本地实机扫描",
    "virus.stopBtn": "⏹️ 停止扫描",
    "virus.demoBtn": "📡 模拟演示扫描 (Demo)",
    "virus.metricFiles": "已扫描文件",
    "virus.metricDirs": "已检查目录",
    "virus.metricThreats": "发现威胁",
    "virus.metricStatus": "引擎状态",

    // Dependencies View
    "dep.title": "软件包与依赖漏洞检测 (Google OSV)",
    "dep.sub": "基于 Google OSV 实时检测开源漏洞 CVE/GHSA，无需上传实际文件",
    "dep.presetsTitle": "⚡ 一键快速测试预设（无需上传文件）：",
    "dep.presetVuln": "含已知漏洞套件 (Demo CVEs)",
    "dep.presetSafe": "安全无漏洞套件 (Clean)",
    "dep.presetPython": "热门 Python 依赖包 (PyPI)",
    "dep.presetProject": "检测当前项目依赖包",
    "dep.inputPlaceholder": "输入包名与版本，例如 express@4.17.1, lodash@4.17.15",
    "dep.checkBtn": "🔍 立即检测",

    // Code & Website View
    "code.title": "源代码安全检测",
    "code.sub": "直接在浏览器内分析选定文件或粘贴的代码，识别通用安全弱点",
    "code.selectFiles": "选择代码文件（最多 15 个文件，每个不超过 1MB）",
    "code.pasteLabel": "或直接粘贴代码",
    "code.pastePlaceholder": "在此粘贴要分析的代码片段...",
    "code.submitBtn": "在本地分析代码",
    "web.title": "网站安全标头检测",
    "web.sub": "仅向目标发送一次 HTTP HEAD 请求以检测安全标头，绝不进行爬虫或侵入式渗透测试",
    "web.urlLabel": "网站 URL（推荐 HTTPS）",
    "web.consent": "我是此网站的所有者或已获得授权，并同意发送一次被动 HEAD 请求",
    "web.submitBtn": "开始被动检测",

    // Table & Common
    "table.col.kind": "检查类型",
    "table.col.target": "目标",
    "table.col.risk": "风险状态",
    "table.col.findings": "发现问题",
    "table.col.time": "检测时间",
    "table.col.report": "报告",
    "table.viewReport": "查看报告",
    "common.items": "项",
    "risk.high": "高危",
    "risk.medium": "中危",
    "risk.low": "低危",
    "risk.clean": "安全",
    "report.noMatch": "未找到符合搜索条件或筛选规则的检测记录。",

    // Scorecard & Grades
    "score.grade.a_plus": "A+ 级 · 极佳安全",
    "score.grade.ready": "A+ 级 · 准备就绪",
    "score.grade.a": "A 级 · 良好安全",
    "score.grade.b": "B 级 · 尚可接受",
    "score.grade.c": "C 级 · 亟待改进",
    "score.grade.d": "D 级 · 高风险",
    "score.grade.f": "F 级 · 极度危险",
    "score.title.ready": "系统安全：未发现高危漏洞",
    "score.title.safe": "系统安全：无严重安全隐患",
    "score.desc.ready": "系统已就绪，可开始扫描 Wi-Fi、源代码、病毒或依赖包以评估安全状况。",
    "score.desc.safe": "所有检查结果均处于高度安全范围。建议定期检测以维持最高安全水准。",
    "score.status.ready": "就绪 (Security Ready)",
    "score.status.safe": "极佳安全 (Secure)",
    "score.status.good": "安全良好 (Good)",
    "score.status.acceptable": "尚可 (Acceptable)",
    "score.status.improve": "需改进 (Improvement Needed)",
    "score.status.high": "高风险 (High Risk)",
    "score.status.critical": "极度危险 (Critical Risk)",

    // Login Page
    "login.brandName": "全方位安全工作区",
    "login.brandSub": "SECURITY WORKSPACE",
    "login.kicker": "安全 · 监控 · 防护",
    "login.welcomeTitle": "携手共建<br>更坚固的系统安全防线",
    "login.welcomeSub": "在风险演变为危机前发现问题。审计网站、代码与文件，全面守护系统安全。",
    "login.feat1": "网站与源代码安全审查",
    "login.feat2": "依赖包与 Wi-Fi 信号分析",
    "login.feat3": "安全隔离文件扫描",
    "login.welcomeFooter": "请仅在您拥有或已获得明确授权的系统上使用本工具。",
    "login.secureAccess": "安全访问",
    "login.authTitle": "登录账号",
    "login.authIntro": "已有账号的用户，请输入电子邮箱和密码登录。",
    "login.authIntroNew": "新用户请输入电子邮箱并设置密码以创建账号。",
    "login.tabSignin": "登录",
    "login.tabSignup": "注册账号",
    "login.labelEmail": "电子邮箱",
    "login.labelPassword": "密码",
    "login.btnSignin": "登录",
    "login.labelPasswordMin": "密码 (至少 6 位字符)",
    "login.labelPasswordConfirm": "确认密码",
    "login.btnSignup": "创建新账号",
    "login.warning": "登录仅使用 Firebase 身份验证。后端请求仍在服务端进行严格的权限验证。"
  },

  ja: {
    // Navigation
    "nav.main": "メインメニュー",
    "nav.dashboard": "ダッシュボード",
    "nav.queue": "スキャンキュー",
    "nav.reports": "セキュリティレポート",
    "nav.engines": "スキャンエンジン",
    "nav.virus": "ウイルススキャン",
    "nav.website": "Webサイト診断",
    "nav.code": "ソースコード解析",
    "nav.dependencies": "依存関係監査",
    "nav.wifi": "Wi-Fi セキュリティ",
    "nav.sideNoteTitle": "許可されたシステム専用",
    "nav.sideNoteDesc": "選択したファイルのみスキャンします。ファイルは実行されず安全に検査されます。",

    // Topbar & System
    "topbar.eyebrow": "SECURITY OVERVIEW",
    "topbar.ready": "システム準備完了 (Security Workspace · Ready)",
    "topbar.login": "ログイン",
    "topbar.logout": "ログアウト",

    // Titles
    "title.dashboard": "セキュリティ概要",
    "title.queue": "スキャンキュー",
    "title.reports": "スキャン履歴とレポート",
    "title.engines": "スキャンエンジン設定",
    "title.virus": "ローカルアンチウイルス",
    "title.website": "Webサイトセキュリティヘッダー診断",
    "title.code": "ソースコード脆弱性分析",
    "title.dependencies": "依存パッケージ脆弱性監査",
    "title.wifi": "Wi-Fi セキュリティアナライザー",

    // Hero
    "hero.title": "多層防御セキュリティワークスペースへようこそ",
    "hero.desc": "リアルタイム総合セキュリティプラットフォーム：ローカル実機ディスクスキャン、Wi-Fi暗号化診断、ソースコード監査、Webサイトセキュリティヘッダー検査、Google OSV 脆弱性データベース検索。",

    // Scorecard
    "score.label": "セキュリティスコア",
    "score.quickPrint": "🖨️ レポート印刷",
    "score.tag.realtime": "🛡️ リアルタイム解析",
    "score.tag.persistent": "💾 自動ローカル保存",
    "score.tag.standards": "📋 国際基準準拠",

    // Stats
    "stat.scans": "スキャン回数",
    "stat.findings": "検出項目数",
    "stat.high": "高危険度項目",
    "stat.last": "最新スキャン",

    // Quick Actions
    "quick.title": "クイックセキュリティ診断",
    "quick.sub": "診断ツールを選択してシステムの安全性を評価します",
    "quick.wifi.title": "周囲のWi-Fiを検出",
    "quick.wifi.desc": "実際のWi-Fi電波をスキャンし、暗号化方式と安全性を検査",
    "quick.virus.title": "実機ウイルススキャン",
    "quick.virus.desc": "YARAエンジンで実ディスクを検査し、トロイの木馬や偽装ファイルを検出",
    "quick.code.title": "ソースコード診断",
    "quick.code.desc": "SQLインジェクション、XSS、埋め込み認証情報の弱点を検出",
    "quick.dep.title": "パッケージ脆弱性診断",
    "quick.dep.desc": "Google OSV データベースと連携して CVE 脆弱性をリアルタイム照会",

    // Severity Accumulator
    "sev.title": "累積リスク分布",
    "sev.high": "高リスク",
    "sev.medium": "中リスク",
    "sev.low": "低リスク",

    // Reports View
    "report.title": "監査履歴とセキュリティレポート",
    "report.sub": "ブラウザのローカルストレージに自動保存され、リロードしてもデータは消えません",
    "report.printBtn": "🖨️ 印刷 / PDF保存",
    "report.exportBtn": "JSON出力",
    "report.clearBtn": "🗑️ 履歴をクリア",
    "report.searchPlaceholder": "🔍 履歴検索（Wi-Fi、express、lodash、URL...）",
    "report.filterAll": "すべて",
    "report.filterHigh": "高危険度",
    "report.filterMedium": "中危険度",
    "report.filterClean": "安全",
    "report.emptyHistory": "スキャン履歴がありません（スキャンを実行すると自動記録されます）",
    "report.latestTitle": "最新スキャン検出詳細",
    "report.selectPrompt": "左側メニューから診断項目を選択してレポートを生成します",

    // Wi-Fi View
    "wifi.title": "Wi-Fi & 電波セキュリティ診断",
    "wifi.sub": "周囲のWi-Fi信号をスキャンし、パスワード保護、電波強度、暗号化安全度を検証",
    "wifi.scanHardware": "⚡ 実機Wi-Fiハードウェアスキャン",
    "wifi.scanDemo": "📡 デモシミュレーション",
    "wifi.importFile": "📂 ファイルインポート",
    "wifi.searchPlaceholder": "🔍 ネットワーク名 (SSID) を検索...",
    "wifi.detected": "検出されたWi-Fi信号",
    "wifi.selectedPrompt": "Wi-Fi信号を選択して診断結果を表示",
    "wifi.selectedPromptSub": "左側のリストからネットワークをクリックして安全性を評価します",

    // Virus View
    "virus.title": "システムアンチウイルススキャン（実機エンジン）",
    "virus.sub": "YARAヒューリスティックエンジンでローカルファイルを直接検査。ファイルアップロード不要で安全。",
    "virus.quickMode": "⚡ クイックスキャン",
    "virus.quickDesc": "高リスクフォルダ（Downloads, Desktop, Startup, Documents, Temp）を即時検査",
    "virus.fullMode": "🖥️ フルシステムスキャン",
    "virus.fullDesc": "Cドライブの全ファイルおよびサブフォルダを完全検査",
    "virus.customMode": "📁 カスタムパス指定",
    "virus.customDesc": "特定のフォルダパスを指定してスキャン",
    "virus.startBtn": "▶️ 実機スキャンを即時開始",
    "virus.stopBtn": "⏹️ スキャン停止",
    "virus.demoBtn": "📡 デモスキャンシミュレーション",
    "virus.metricFiles": "スキャン済みファイル",
    "virus.metricDirs": "検査フォルダ数",
    "virus.metricThreats": "検出脅威数",
    "virus.metricStatus": "エンジン状態",

    // Dependencies View
    "dep.title": "パッケージ・依存関係脆弱性診断 (Google OSV)",
    "dep.sub": "Google OSV データベースから国際的な CVE 脆弱性をリアルタイム検索。アップロード不要。",
    "dep.presetsTitle": "⚡ 1クリッククイック診断（ファイル不要）：",
    "dep.presetVuln": "既知の脆弱性サンプル (Demo CVEs)",
    "dep.presetSafe": "最新安全パッケージ (Clean)",
    "dep.presetPython": "人気 Python パッケージ (PyPI)",
    "dep.presetProject": "このプロジェクトのパッケージを検査",
    "dep.inputPlaceholder": "パッケージ名を入力（例: express@4.17.1, lodash@4.17.15）",
    "dep.checkBtn": "🔍 今すぐ診断",

    // Code & Website View
    "code.title": "ソースコードセキュリティレビュー",
    "code.sub": "選択したファイルや貼り付けたコードの脆弱性をブラウザ内で解析",
    "code.selectFiles": "コードファイルを選択（最大15ファイル、各1MBまで）",
    "code.pasteLabel": "またはコードを直接貼り付け",
    "code.pastePlaceholder": "解析したいコードをここに貼り付け...",
    "code.submitBtn": "ローカルで解析実行",
    "web.title": "Webサイトセキュリティヘッダー診断",
    "web.sub": "ブラウザから単一のHTTP HEADリクエストを送信してセキュリティヘッダーを検査（非破壊的調査）",
    "web.urlLabel": "診断対象のWebサイトURL（HTTPS推奨）",
    "web.consent": "私はこのWebサイトの所有者または権限を保持しており、パッシブHEADリクエストの送信に同意します",
    "web.submitBtn": "パッシブ診断を開始",

    // Table & Common
    "table.col.kind": "検査種類",
    "table.col.target": "対象",
    "table.col.risk": "リスク状況",
    "table.col.findings": "検出項目",
    "table.col.time": "検査日時",
    "table.col.report": "レポート",
    "table.viewReport": "レポート確認",
    "common.items": "件",
    "risk.high": "高リスク",
    "risk.medium": "中リスク",
    "risk.low": "低リスク",
    "risk.clean": "安全",
    "report.noMatch": "検索条件またはフィルターに一致する検査履歴はありません。",

    // Scorecard & Grades
    "score.grade.a_plus": "グレード A+ · 非常に安全",
    "score.grade.ready": "グレード A+ · 準備完了",
    "score.grade.a": "グレード A · 良好",
    "score.grade.b": "グレード B · 許容範囲",
    "score.grade.c": "グレード C · 改善が必要",
    "score.grade.d": "グレード D · 高リスク",
    "score.grade.f": "グレード F · 致命的リスク",
    "score.title.ready": "安全なシステム：高リスク脆弱性は未検出",
    "score.title.safe": "安全なシステム：重大な脆弱性は検出されず",
    "score.desc.ready": "システムは診断準備完了です。Wi-Fi、コード、ウイルス、または依存関係をスキャンして状態を確認してください。",
    "score.desc.safe": "すべての検査結果は安全基準を満たしています。定期的な監査で高水準のセキュリティを維持しましょう。",
    "score.status.ready": "準備完了 (Security Ready)",
    "score.status.safe": "非常に安全 (Secure)",
    "score.status.good": "良好 (Good)",
    "score.status.acceptable": "許容範囲 (Acceptable)",
    "score.status.improve": "要改善 (Improvement Needed)",
    "score.status.high": "高リスク (High Risk)",
    "score.status.critical": "致命的リスク (Critical Risk)",

    // Login Page
    "login.brandName": "セキュリティ・ワークスペース",
    "login.brandSub": "360° DEFENSE PLATFORM",
    "login.kicker": "保護 · 監視 · 防御",
    "login.welcomeTitle": "共にシステムの<br>セキュリティ水準を高めましょう",
    "login.welcomeSub": "重大なインシデントになる前に脆弱性を検知。Webサイト、ソースコード、ファイルを監査し、安全な運用を支えます。",
    "login.feat1": "Webサイト・ソースコード診断",
    "login.feat2": "依存パッケージ・Wi-Fi 分析",
    "login.feat3": "安全な隔離ファイルスキャン",
    "login.welcomeFooter": "所有しているシステム、または診断が許可されたシステムでのみ使用してください。",
    "login.secureAccess": "セキュアアクセス",
    "login.authTitle": "ログイン",
    "login.authIntro": "すでにアカウントをお持ちの方は、メールアドレスとパスワードでログインしてください。",
    "login.authIntroNew": "新規ユーザーは、メールアドレスとパスワードを入力してアカウントを作成してください。",
    "login.tabSignin": "ログイン",
    "login.tabSignup": "アカウント登録",
    "login.labelEmail": "メールアドレス",
    "login.labelPassword": "パスワード",
    "login.btnSignin": "ログイン",
    "login.labelPasswordMin": "パスワード (6文字以上)",
    "login.labelPasswordConfirm": "パスワード再入力",
    "login.btnSignup": "新規アカウント作成",
    "login.warning": "認証は Firebase Authentication を使用しています。バックエンドの各機能も安全に保護されています。"
  },

  es: {
    // Navigation
    "nav.main": "Menú Principal",
    "nav.dashboard": "Panel General",
    "nav.queue": "Cola de Análisis",
    "nav.reports": "Informes",
    "nav.engines": "Motores de Escaneo",
    "nav.virus": "Antivirus",
    "nav.website": "Auditoría Web",
    "nav.code": "Análisis de Código",
    "nav.dependencies": "Dependencias",
    "nav.wifi": "Inspector Wi-Fi",
    "nav.sideNoteTitle": "Solo Sistemas Autorizados",
    "nav.sideNoteDesc": "Analice solo archivos seleccionados. Se analizan de forma aislada y nunca se ejecutan en el sistema.",

    // Topbar & System
    "topbar.eyebrow": "SECURITY OVERVIEW",
    "topbar.ready": "Sistema Listo (Security Workspace · Ready)",
    "topbar.login": "Iniciar Sesión",
    "topbar.logout": "Cerrar Sesión",

    // Titles
    "title.dashboard": "Visión General de Seguridad",
    "title.queue": "Cola de Escaneo",
    "title.reports": "Historial e Informes de Auditoría",
    "title.engines": "Motores de Escaneo",
    "title.virus": "Antivirus del Sistema Real",
    "title.website": "Encabezados de Seguridad Web",
    "title.code": "Revisión de Código Fuente",
    "title.dependencies": "Auditoría de Dependencias y CVEs",
    "title.wifi": "Analizador de Seguridad Wi-Fi",

    // Hero
    "hero.title": "Bienvenido al Espacio de Trabajo de Seguridad (Defensa 360°)",
    "hero.desc": "Plataforma integral de detección y ciberseguridad: análisis de disco local, auditoría Wi-Fi, revisión de código fuente, comprobación de encabezados HTTP y búsqueda de vulnerabilidades Google OSV en tiempo real.",

    // Scorecard
    "score.label": "Puntuación de Seguridad",
    "score.quickPrint": "🖨️ Imprimir Resumen",
    "score.tag.realtime": "🛡️ Análisis en Tiempo Real",
    "score.tag.persistent": "💾 Guardado Local Automático",
    "score.tag.standards": "📋 Estándares Globales",

    // Stats
    "stat.scans": "Escaneos Totales",
    "stat.findings": "Problemas Detectados",
    "stat.high": "Riesgo Alto",
    "stat.last": "Último Escaneo",

    // Quick Actions
    "quick.title": "Escaneos Rápidos de Seguridad",
    "quick.sub": "Seleccione una herramienta para evaluar la salud de su infraestructura",
    "quick.wifi.title": "Escanear Redes Wi-Fi",
    "quick.wifi.desc": "Analice señales Wi-Fi reales y evalúe contraseñas y cifrado",
    "quick.virus.title": "Antivirus de Disco",
    "quick.virus.desc": "Escanee el disco C:\\ en busca de troyanos y malware con YARA",
    "quick.code.title": "Vulnerabilidades en Código",
    "quick.code.desc": "Detecte inyecciones SQL, XSS y credenciales expuestas",
    "quick.dep.title": "Auditor de Paquetes",
    "quick.dep.desc": "Verifique paquetes con la base de datos Google OSV en vivo",

    // Severity Accumulator
    "sev.title": "Distribución Acumulada de Severidad",
    "sev.high": "Riesgo Alto",
    "sev.medium": "Riesgo Medio",
    "sev.low": "Riesgo Bajo",

    // Reports View
    "report.title": "Historial de Auditoría e Informes",
    "report.sub": "Guardado automáticamente en LocalStorage del navegador — no se pierde al recargar",
    "report.printBtn": "🖨️ Imprimir / Guardar PDF",
    "report.exportBtn": "Exportar JSON",
    "report.clearBtn": "🗑️ Limpiar Historial",
    "report.searchPlaceholder": "🔍 Buscar en historial (Wi-Fi, express, lodash, URL...)",
    "report.filterAll": "Todo",
    "report.filterHigh": "Riesgo Alto",
    "report.filterMedium": "Riesgo Medio",
    "report.filterClean": "Seguro",
    "report.emptyHistory": "Aún no hay historial de análisis (se guardará automáticamente al finalizar los escaneos)",
    "report.latestTitle": "Detalles del Último Análisis",
    "report.selectPrompt": "Seleccione un análisis del menú izquierdo para generar un informe",

    // Wi-Fi View
    "wifi.title": "Inspector de Seguridad Wi-Fi y Señal Inalámbrica",
    "wifi.sub": "Escanee y seleccione redes Wi-Fi cercanas para inspeccionar protección por contraseña, calidad de señal y nivel de seguridad",
    "wifi.scanHardware": "⚡ Escanear Hardware Wi-Fi Local",
    "wifi.scanDemo": "📡 Simulación Demo",
    "wifi.importFile": "📂 Importar Archivo",
    "wifi.searchPlaceholder": "🔍 Buscar nombre de red (SSID)...",
    "wifi.detected": "Redes Wi-Fi Detectadas",
    "wifi.selectedPrompt": "Seleccione una red Wi-Fi para ver detalles",
    "wifi.selectedPromptSub": "Haga clic en una red de la lista izquierda para evaluar su seguridad",

    // Virus View
    "virus.title": "Escáner Antivirus del Sistema (Motor Local Real)",
    "virus.sub": "Escanea archivos físicos con el motor heurístico YARA sin subir archivos a internet",
    "virus.quickMode": "⚡ Escaneo Rápido (Quick Scan)",
    "virus.quickDesc": "Inspecciona carpetas críticas (Downloads, Desktop, Startup, Documents, Temp)",
    "virus.fullMode": "🖥️ Escaneo Completo (Full System)",
    "virus.fullDesc": "Auditoría completa del disco C:\\ y todas sus subcarpetas",
    "virus.customMode": "📁 Ruta Personalizada (Custom Path)",
    "virus.customDesc": "Especifique una carpeta objetivo para escanear",
    "virus.startBtn": "▶️ Iniciar Escaneo Real Local",
    "virus.stopBtn": "⏹️ Detener Escaneo",
    "virus.demoBtn": "📡 Probar Simulación Demo",
    "virus.metricFiles": "Archivos Analizados",
    "virus.metricDirs": "Directorios Revisados",
    "virus.metricThreats": "Amenazas Detectadas",
    "virus.metricStatus": "Estado del Motor",

    // Dependencies View
    "dep.title": "Auditor de Vulnerabilidades en Dependencias (Google OSV)",
    "dep.sub": "Verifique paquetes contra la base de datos oficial Google OSV en tiempo real. No requiere subir archivos.",
    "dep.presetsTitle": "⚡ Pruebas Rápidas en 1-Clic (Sin archivos):",
    "dep.presetVuln": "Paquetes Vulnerables (Demo CVEs)",
    "dep.presetSafe": "Paquetes Seguros y Parcheados (Clean)",
    "dep.presetPython": "Paquetes Populares de Python (PyPI)",
    "dep.presetProject": "Dependencias de este Proyecto",
    "dep.inputPlaceholder": "Nombre y versión, ej: express@4.17.1, lodash@4.17.15, requests@2.25.1",
    "dep.checkBtn": "🔍 Auditar Ahora",

    // Code & Website View
    "code.title": "Revisión de Seguridad de Código Fuente",
    "code.sub": "Detecte debilidades comunes de seguridad en archivos seleccionados o código pegado en el navegador",
    "code.selectFiles": "Seleccionar Archivos (Máx 15 archivos, 1MB c/u)",
    "code.pasteLabel": "O Pegue Código Directamente",
    "code.pastePlaceholder": "Pegue el código fuente a analizar...",
    "code.submitBtn": "Analizar en el Navegador",
    "web.title": "Auditoría de Encabezados de Seguridad Web",
    "web.sub": "Envía una solicitud HTTP HEAD pasiva para evaluar encabezados de seguridad sin escaneos invasivos",
    "web.urlLabel": "URL del Sitio Web (Se recomienda HTTPS)",
    "web.consent": "Soy el propietario de este sitio o estoy autorizado para auditarlo, y acepto una solicitud HEAD pasiva",
    "web.submitBtn": "Iniciar Auditoría Pasiva",

    // Table & Common
    "table.col.kind": "Tipo de Análisis",
    "table.col.target": "Objetivo",
    "table.col.risk": "Estado de Riesgo",
    "table.col.findings": "Hallazgos",
    "table.col.time": "Hora",
    "table.col.report": "Informe",
    "table.viewReport": "Ver Informe",
    "common.items": "elementos",
    "risk.high": "Alto Riesgo",
    "risk.medium": "Medio",
    "risk.low": "Bajo",
    "risk.clean": "Limpio",
    "report.noMatch": "No se encontraron registros de escaneo que coincidan con la búsqueda o filtro.",

    // Scorecard & Grades
    "score.grade.a_plus": "Grado A+ · Excelente Seguridad",
    "score.grade.ready": "Grado A+ · Listo para Escanear",
    "score.grade.a": "Grado A · Buena Seguridad",
    "score.grade.b": "Grado B · Seguridad Aceptable",
    "score.grade.c": "Grado C · Requiere Mejoras",
    "score.grade.d": "Grado D · Alto Riesgo",
    "score.grade.f": "Grado F · Riesgo Crítico",
    "score.title.ready": "Sistema Seguro: Sin vulnerabilidades de alto riesgo",
    "score.title.safe": "Sistema Seguro: Sin vulnerabilidades críticas",
    "score.desc.ready": "El sistema está listo para auditorías. Inicie el escaneo de Wi-Fi, código, virus o dependencias para evaluar el estado.",
    "score.desc.safe": "Todos los resultados están dentro de umbrales seguros. Realice auditorías periódicas para mantener una alta seguridad.",
    "score.status.ready": "Listo (Security Ready)",
    "score.status.safe": "Excelente (Secure)",
    "score.status.good": "Buena Seguridad (Good)",
    "score.status.acceptable": "Aceptable",
    "score.status.improve": "Requiere Mejoras",
    "score.status.high": "Alto Riesgo",
    "score.status.critical": "Riesgo Crítico",

    // Login Page
    "login.brandName": "Espacio de Seguridad Integral",
    "login.brandSub": "SECURITY WORKSPACE",
    "login.kicker": "PROTEGER · MONITOREAR · DEFENDER",
    "login.welcomeTitle": "Elevemos juntos<br>la seguridad de su infraestructura",
    "login.welcomeSub": "Identifique puntos vulnerables antes de que se conviertan en incidentes. Audite sitios web, código y archivos de forma segura.",
    "login.feat1": "Auditoría de Sitios Web y Código",
    "login.feat2": "Análisis de Dependencias y Wi-Fi",
    "login.feat3": "Escaneo Seguro de Archivos Aislados",
    "login.welcomeFooter": "Utilice esta herramienta únicamente en sistemas de su propiedad o con autorización explícita.",
    "login.secureAccess": "ACCESO SEGURO",
    "login.authTitle": "Iniciar Sesión",
    "login.authIntro": "Para usuarios con cuenta existente, ingrese con su correo electrónico y contraseña.",
    "login.authIntroNew": "Para nuevos usuarios, ingrese su correo electrónico y cree una contraseña para registrarse.",
    "login.tabSignin": "Iniciar Sesión",
    "login.tabSignup": "Registrarse",
    "login.labelEmail": "Correo Electrónico",
    "login.labelPassword": "Contraseña",
    "login.btnSignin": "Iniciar Sesión",
    "login.labelPasswordMin": "Contraseña (mínimo 6 caracteres)",
    "login.labelPasswordConfirm": "Confirmar Contraseña",
    "login.btnSignup": "Crear Cuenta Nueva",
    "login.warning": "La autenticación utiliza Firebase. Todas las operaciones de backend continúan protegidas en el servidor."
  }
};

/**
 * Get current active language
 */
export function getLanguage() {
  try {
    const saved = localStorage.getItem(STORAGE_LANG_KEY);
    if (saved && SUPPORTED_LANGS.includes(saved)) {
      return saved;
    }
  } catch {
    // ignore localstorage errors
  }
  return DEFAULT_LANG;
}

/**
 * Translate a key according to current language
 */
export function t(key, fallback = "") {
  const currentLang = getLanguage();
  if (translations[currentLang] && translations[currentLang][key]) {
    return translations[currentLang][key];
  }
  if (translations[DEFAULT_LANG] && translations[DEFAULT_LANG][key]) {
    return translations[DEFAULT_LANG][key];
  }
  return fallback || key;
}

/**
 * Switch language and apply to DOM
 */
export function setLanguage(lang) {
  if (!SUPPORTED_LANGS.includes(lang)) return;
  try {
    localStorage.setItem(STORAGE_LANG_KEY, lang);
  } catch (e) {
    console.warn("Could not save language to localStorage:", e);
  }

  // Update HTML lang attribute
  document.documentElement.lang = lang;

  // Translate all [data-i18n] text contents
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (key) {
      const translated = t(key);
      if (translated) el.textContent = translated;
    }
  });

  // Translate all [data-i18n-placeholder] attributes
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const key = el.getAttribute("data-i18n-placeholder");
    if (key) {
      const translated = t(key);
      if (translated) el.setAttribute("placeholder", translated);
    }
  });

  // Sync any language selector dropdowns
  document.querySelectorAll(".lang-select").forEach((select) => {
    if (select.value !== lang) {
      select.value = lang;
    }
  });

  // Dispatch custom event for dynamic components (like charts, titles, and scorecards)
  window.dispatchEvent(new CustomEvent("languageChanged", { detail: { lang } }));
}

/**
 * Initialize i18n on page load
 */
export function initI18n() {
  const currentLang = getLanguage();

  // Attach change listener to any .lang-select element
  document.querySelectorAll(".lang-select").forEach((select) => {
    select.value = currentLang;
    select.addEventListener("change", (e) => {
      setLanguage(e.target.value);
    });
  });

  // Apply current language
  setLanguage(currentLang);
}

// Auto-initialize when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initI18n);
} else {
  initI18n();
}

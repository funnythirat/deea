import { initializeApp } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-app.js";
import {
  createUserWithEmailAndPassword,
  getAuth,
  onAuthStateChanged,
  signInWithEmailAndPassword
} from "https://www.gstatic.com/firebasejs/11.10.0/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyAjyXKgx8Ox-s9tBsP2w2psXWM0EVUJCOk",
  authDomain: "deea-9ed32.firebaseapp.com",
  projectId: "deea-9ed32",
  storageBucket: "deea-9ed32.firebasestorage.app",
  messagingSenderId: "649361533233",
  appId: "1:649361533233:web:a2f979984a76f67f222810"
};

const authMessage = document.getElementById("authMessage");
const authErrorMessages = {
  "auth/email-already-in-use": "อีเมลนี้มีบัญชีอยู่แล้ว",
  "auth/invalid-email": "รูปแบบอีเมลไม่ถูกต้อง",
  "auth/invalid-credential": "อีเมลหรือรหัสผ่านไม่ถูกต้อง",
  "auth/network-request-failed": "เชื่อมต่อ Firebase ไม่สำเร็จ ตรวจสอบอินเทอร์เน็ตแล้วลองอีกครั้ง",
  "auth/operation-not-allowed": "ยังไม่ได้เปิด Email/Password ใน Firebase Console",
  "auth/weak-password": "รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร",
  "auth/too-many-requests": "มีคำขอมากเกินไป กรุณารอสักครู่แล้วลองใหม่",
  "auth/user-not-found": "ไม่พบบัญชีผู้ใช้สำหรับอีเมลนี้",
  "auth/wrong-password": "รหัสผ่านไม่ถูกต้อง"
};

function setAuthMessage(message, type = "") {
  authMessage.textContent = message;
  authMessage.className = "message" + (type ? " " + type : "");
}

function displayAuthError(error) {
  console.error("Firebase Authentication request failed.", error);
  setAuthMessage(
    authErrorMessages[error.code] || "ดำเนินการไม่สำเร็จ กรุณาตรวจการตั้งค่า Firebase Authentication แล้วลองใหม่",
    "error"
  );
}

const authModes = {
  existing: {
    button: document.getElementById("existingAccountTab"),
    panel: document.getElementById("loginPanel"),
    title: "เข้าสู่ระบบ",
    intro: "สำหรับผู้ที่มีบัญชีอยู่แล้ว ให้เข้าสู่ระบบด้วยอีเมลและรหัสผ่าน"
  },
  new: {
    button: document.getElementById("newAccountTab"),
    panel: document.getElementById("createAccountPanel"),
    title: "สมัครบัญชีใหม่",
    intro: "สำหรับผู้ที่ยังไม่เคยสมัคร กรอกอีเมลและตั้งรหัสผ่านเพื่อสร้างบัญชี"
  }
};

function selectAuthMode(mode) {
  for (const [name, option] of Object.entries(authModes)) {
    const isSelected = name === mode;
    option.button.setAttribute("aria-pressed", String(isSelected));
    option.panel.hidden = !isSelected;
  }
  document.getElementById("authTitle").textContent = authModes[mode].title;
  document.getElementById("authIntro").textContent = authModes[mode].intro;
  setAuthMessage("");
}

authModes.existing.button.addEventListener("click", () => selectAuthMode("existing"));
authModes.new.button.addEventListener("click", () => selectAuthMode("new"));

try {
  const auth = getAuth(initializeApp(firebaseConfig));
  onAuthStateChanged(auth, (user) => {
    if (user) location.replace("./");
  }, (error) => {
    displayAuthError(error);
  });

  document.getElementById("loginForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = document.getElementById("loginButton");
    button.disabled = true;
    button.textContent = "กำลังเข้าสู่ระบบ...";
    try {
      await signInWithEmailAndPassword(
        auth,
        document.getElementById("loginEmail").value.trim(),
        document.getElementById("loginPassword").value
      );
    } catch (error) {
      displayAuthError(error);
    } finally {
      button.disabled = false;
      button.textContent = "เข้าสู่ระบบ";
    }
  });

  document.getElementById("createAccountForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = document.getElementById("createPassword").value;
    const passwordConfirm = document.getElementById("createPasswordConfirm").value;
    if (password !== passwordConfirm) {
      setAuthMessage("รหัสผ่านและการยืนยันรหัสผ่านไม่ตรงกัน", "error");
      document.getElementById("createPasswordConfirm").focus();
      return;
    }
    const button = document.getElementById("createAccountButton");
    button.disabled = true;
    button.textContent = "กำลังสร้างบัญชี...";
    try {
      await createUserWithEmailAndPassword(
        auth,
        document.getElementById("createEmail").value.trim(),
        password
      );
    } catch (error) {
      displayAuthError(error);
    } finally {
      button.disabled = false;
      button.textContent = "สมัครบัญชีใหม่";
    }
  });
} catch (error) {
  console.error("Firebase Authentication could not be initialized.", error);
  setAuthMessage("เริ่ม Firebase Authentication ไม่สำเร็จ ตรวจสอบ Firebase config แล้วลองโหลดหน้าใหม่", "error");
}

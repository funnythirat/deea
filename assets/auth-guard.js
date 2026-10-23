import { getApp } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-app.js";
import { getAuth, onAuthStateChanged, signOut } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-auth.js";

const appShell = document.getElementById("appShell");
try {
  const app = getApp();
  const auth = getAuth(app);
  onAuthStateChanged(auth, (user) => {
    if (!user) {
      location.replace("login.html");
      return;
    }
    appShell.hidden = false;
  }, (error) => {
    console.error("Firebase Authentication state could not be read.", error);
    location.replace("login.html");
  });

  document.getElementById("signOutButton").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await signOut(auth);
    } catch (error) {
      console.error("Firebase sign-out failed.", error);
      button.disabled = false;
      window.alert("ออกจากระบบไม่สำเร็จ กรุณาลองอีกครั้ง");
    }
  });
} catch (error) {
  console.error("Firebase could not be initialized.", error);
  location.replace("login.html");
}

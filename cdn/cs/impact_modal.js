// impact_modal.js — harmless Modal PoC (non-destructive)
// Shows a modal so reviewer can see external script executed.
// Will auto-close when OK clicked.

console.log("Modal PoC loaded");

try {
  // backdrop
  var backdrop = document.createElement('div');
  backdrop.style.position = 'fixed';
  backdrop.style.left = '0';
  backdrop.style.top = '0';
  backdrop.style.width = '100%';
  backdrop.style.height = '100%';
  backdrop.style.background = 'rgba(0,0,0,0.5)';
  backdrop.style.zIndex = '2147483646';
  backdrop.id = 'inAuthPoCBackdrop';

  // modal
  var modal = document.createElement('div');
  modal.style.position = 'fixed';
  modal.style.left = '50%';
  modal.style.top = '50%';
  modal.style.transform = 'translate(-50%, -50%)';
  modal.style.background = '#fff';
  modal.style.padding = '18px';
  modal.style.borderRadius = '8px';
  modal.style.boxShadow = '0 8px 28px rgba(0,0,0,0.35)';
  modal.style.zIndex = '2147483647';
  modal.id = 'inAuthPoCModal';

  modal.innerHTML = '<h3 style="margin:0 0 8px 0;font-family:system-ui">inAuth PoC</h3>'
    + '<p style="margin:0 0 12px 0;font-family:system-ui">External script executed (harmless). This is a visual proof only.</p>'
    + '<div style="text-align:right;"><button id="inAuthPoCBtn" style="padding:8px 12px;border-radius:6px;border:0;cursor:pointer">OK</button></div>';

  document.documentElement.appendChild(backdrop);
  document.documentElement.appendChild(modal);

  // focus button for accessibility
  var btn = document.getElementById('inAuthPoCBtn');
  if (btn) btn.focus();

  // close handler
  function closePoC(){
    try {
      var b = document.getElementById('inAuthPoCBackdrop');
      var m = document.getElementById('inAuthPoCModal');
      if (b && b.parentNode) b.parentNode.removeChild(b);
      if (m && m.parentNode) m.parentNode.removeChild(m);
    } catch(e){}
  }
  if (btn) btn.addEventListener('click', closePoC);

  // auto-clean after 20s in case reviewer doesn't click
  setTimeout(closePoC, 20000);

} catch (e) {
  console.log("Modal PoC error:", e);
}

(function () {
  const $ = (id) => document.getElementById(id);
  let map, marker, mapReady = false, pendingVehicle = null, current = null;

  window.initMap = function () {
    mapReady = true;
    if (pendingVehicle) showOnMap(pendingVehicle);
  };

  function alertBox(type, text) {
    $('msg').innerHTML = text
      ? `<div class="alert alert-${type} py-2 mb-0">${escapeHtml(text)}</div>` : '';
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  async function api(url, opts = {}) {
    const r = await fetch(url, {
      ...opts,
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.APP.csrf },
    });
    let j = {};
    try { j = await r.json(); } catch (e) { /* risposta non JSON */ }
    if (r.status === 401) { location.reload(); }
    if (!r.ok || !j.ok) throw new Error(j.error || 'Errore di rete');
    return j;
  }

  function render(v) {
    current = v;
    $('card').classList.remove('d-none');
    $('vPlate').textContent = v.plate;
    $('vInfo').textContent = Object.values(v.info || {}).filter(Boolean).join(' ');
    const has = v.lat !== null && v.lng !== null;
    const b = $('vBadge');
    b.className = 'badge rounded-pill ' + (has ? 'text-bg-success' : 'text-bg-secondary');
    b.textContent = has ? 'Posizione nota' : 'Nessuna posizione';
    $('vCoords').textContent = has
      ? `${v.lat.toFixed(6)}, ${v.lng.toFixed(6)}`
        + (v.acc ? ` · ±${Math.round(v.acc)} m` : '')
        + (v.updated ? ` · ${v.updated}` : '')
        + (v.source ? ` · ${v.source}` : '')
      : 'Usa il pulsante per registrare la posizione.';
    const nav = $('btnNav');
    if (has) {
      nav.href = `https://www.google.com/maps/search/?api=1&query=${v.lat},${v.lng}`;
      nav.classList.remove('d-none');
    } else { nav.classList.add('d-none'); }
    showOnMap(v);
  }

  function showOnMap(v) {
    const el = $('map');
    if (v.lat === null || v.lng === null) { el.classList.add('d-none'); return; }
    el.classList.remove('d-none');
    if (!mapReady) { pendingVehicle = v; return; }
    const pos = { lat: v.lat, lng: v.lng };
    if (!map) {
      map = new google.maps.Map(el, { center: pos, zoom: 17, mapTypeControl: false, streetViewControl: false });
      marker = new google.maps.Marker({ map, position: pos });
    }
    marker.setPosition(pos);
    marker.setTitle(v.plate);
    map.setCenter(pos);
    map.setZoom(17);
    google.maps.event.trigger(map, 'resize');
  }

  async function search() {
    const plate = $('plate').value.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
    if (plate.length < 4) { alertBox('warning', 'Inserisci una targa valida'); return; }
    alertBox('info', 'Ricerca in corso…');
    try {
      const j = await api('api/vehicle.php?plate=' + encodeURIComponent(plate));
      alertBox('', ''); render(j.vehicle);
    } catch (e) {
      $('card').classList.add('d-none'); $('map').classList.add('d-none');
      alertBox('danger', e.message);
    }
  }

  function savePosition() {
    if (!current) return;
    if (!navigator.geolocation) { alertBox('danger', 'Geolocalizzazione non supportata'); return; }
    if (!window.isSecureContext) { alertBox('danger', 'Serve HTTPS per usare il GPS del dispositivo'); return; }
    const btn = $('btnGps'); btn.disabled = true;
    alertBox('info', 'Acquisizione posizione GPS…');
    navigator.geolocation.getCurrentPosition(async (p) => {
      try {
        const j = await api('api/position.php', {
          method: 'POST',
          body: JSON.stringify({ plate: current.plate, lat: p.coords.latitude, lng: p.coords.longitude, accuracy: p.coords.accuracy }),
        });
        alertBox('success', 'Posizione salvata in EG Auto'); render(j.vehicle);
      } catch (e) { alertBox('danger', e.message); }
      btn.disabled = false;
    }, (err) => {
      const m = { 1: 'Permesso di localizzazione negato', 2: 'Posizione non disponibile', 3: 'Timeout GPS' };
      alertBox('danger', m[err.code] || 'Errore GPS'); btn.disabled = false;
    }, { enableHighAccuracy: true, timeout: 20000, maximumAge: 0 });
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!$('btnSearch')) return;
    $('btnSearch').addEventListener('click', search);
    $('plate').addEventListener('keydown', (e) => { if (e.key === 'Enter') search(); });
    $('btnGps').addEventListener('click', savePosition);
  });
})();

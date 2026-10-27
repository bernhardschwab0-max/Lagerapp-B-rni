/* Börnis Backstube – Zugang (Chef / Mitarbeiter) und Protokoll
   Dieselbe Datei liegt in der Lager-, Bestell- und Rezept-App (bei Änderungen in allen drei Repos ersetzen).

   - Chef: Code mit mindestens 6 Ziffern. Er entschlüsselt den jsonbin-Generalschlüssel, der auf dem Gerät
     nur verschlüsselt liegt (AES-GCM, Schlüssel per PBKDF2 aus dem Code).
   - Mitarbeiter: eigener 4-stelliger Code. Gearbeitet wird mit dem Mitarbeiter-Schlüssel (jsonbin Access Key:
     darf lesen und ändern, aber nichts löschen oder neu anlegen).
   - Protokoll: wer wann was gemacht hat. Einträge sammeln sich auf dem Gerät und gehen gebündelt in den
     Team-Speicher (ohne Internet später). Behalten werden 60 Tage, höchstens 600 Einträge.
   Namen, Codes und Schlüssel stehen nie im Programmcode, nur im Team-Speicher bzw. auf dem Gerät. */
window.Zugang = (function () {
  'use strict';
  const VERSION = '1.0';
  const API = 'https://api.jsonbin.io/v3';
  const LS_GERAET = 'zugang_geraet';
  const LS_TEAM = 'zugang_team';
  const LS_QUEUE = 'zugang_protokoll';
  const SS_SITZUNG = 'zugang_sitzung';
  const PROTOKOLL_TAGE = 60;
  const PROTOKOLL_MAX = 600;
  const ITER = 250000;
  // Automatisch abmelden (damit am Firmen-Tablet niemand unter fremdem Namen weiterarbeitet):
  // Geräte mit Mitarbeiter-Zugang: 5 Min. im Hintergrund oder 20 Min. ohne Antippen; reine Chef-Geräte: 30 Min. im Hintergrund
  const HINTERGRUND_MIN = 30;
  const HINTERGRUND_GEMEINSAM_MIN = 5;
  const UNTAETIG_GEMEINSAM_MIN = 20;
  const APP_NAMEN = { lager: 'Lager-App', bestell: 'Bestell-App', rezept: 'Rezept-App' };
  const APP_PFADE = { lager: 'Lagerapp-B-rni', bestell: 'Bestellapp-Boerni', rezept: 'Rezeptapp-Boerni' };

  let app = '';
  let nurChef = false;
  let sitzung = null;

  // ---------- Helfer ----------
  const lade = (k, f) => { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : f; } catch (e) { return f; } };
  const speichere = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch (e) { return false; } };
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const b64 = (buf) => { let s = ''; new Uint8Array(buf).forEach((b) => { s += String.fromCharCode(b); }); return btoa(s); };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const zufall = (n) => crypto.getRandomValues(new Uint8Array(n));
  const neueId = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  async function sha256hex(text) {
    const h = await crypto.subtle.digest('SHA-256', enc.encode(text));
    return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  async function schluesselAusCode(code, salt, iter) {
    const basis = await crypto.subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' }, basis, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function verschluesseln(text, code) {
    const salt = zufall(16), iv = zufall(12);
    const k = await schluesselAusCode(code, salt, ITER);
    const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, enc.encode(text));
    return { v: 1, iter: ITER, salt: b64(salt), iv: b64(iv), data: b64(data) };
  }
  async function entschluesseln(box, code) {
    const k = await schluesselAusCode(code, unb64(box.salt), box.iter || ITER);
    const data = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, k, unb64(box.data));
    return dec.decode(data);
  }
  const codeHash = (salt, code) => sha256hex(salt + ':' + code);

  // ---------- Gerät ----------
  const geraet = () => lade(LS_GERAET, {}) || {};
  const geraetSetzen = (aenderung) => { const g = { ...geraet(), ...aenderung }; speichere(LS_GERAET, g); return g; };

  // Alte Einstellungen der Apps (Generalschlüssel im Klartext) – werden beim ersten Start übernommen und verschlüsselt
  function altKonfig() {
    const out = {};
    try {
      const a = localStorage.getItem('jsonbin_apikey'), b = localStorage.getItem('jsonbin_binid');
      if (a) out.key = a;
      if (b) out.lagerBin = b;
      const be = lade('bestellapp_config', null);
      if (be) { if (be.apiKey && !out.key) out.key = be.apiKey; if (be.lagerBin && !out.lagerBin) out.lagerBin = be.lagerBin; if (be.bestellBin) out.bestellBin = be.bestellBin; }
      const re = lade('rezeptapp_config', null);
      if (re) { if (re.apiKey && !out.key) out.key = re.apiKey; if (re.lagerBin && !out.lagerBin) out.lagerBin = re.lagerBin; }
    } catch (e) {}
    return out;
  }
  function altSchluesselEntfernen() {
    try {
      localStorage.removeItem('jsonbin_apikey');
      const be = lade('bestellapp_config', null);
      if (be && be.apiKey) { delete be.apiKey; speichere('bestellapp_config', be); }
      const re = lade('rezeptapp_config', null);
      if (re && re.apiKey) { delete re.apiKey; speichere('rezeptapp_config', re); }
    } catch (e) {}
  }

  // Einrichtungs-Link: #zugang=<base64 JSON>; alte Links #setup=<base64 Schlüssel|Lager|Bestell> gehen auch
  function linkLesen(text) {
    const t = String(text || '').trim();
    let m = t.match(/#zugang=([^\s#]+)/);
    if (m) {
      try {
        const roh = decodeURIComponent(m[1]).replace(/-/g, '+').replace(/_/g, '/');
        const d = JSON.parse(dec.decode(unb64(roh)));
        if (d && (d.mk || d.chef) && d.lagerBin) return { neu: d };
      } catch (e) {}
      return null;
    }
    m = t.match(/#setup=([^\s#]+)/);
    if (m) {
      try {
        const p = atob(decodeURIComponent(m[1])).split('|');
        if (p.length >= 2 && p[0] && p[1]) return { alt: { key: p[0].trim(), lagerBin: p[1].trim(), bestellBin: (p[2] || '').trim() || undefined } };
      } catch (e) {}
    }
    return null;
  }
  function linkBauen(zielApp, mitChef) {
    const g = geraet();
    const d = { v: 1, lagerBin: g.lagerBin, bestellBin: g.bestellBin, teamBin: g.teamBin, mk: g.mk };
    if (mitChef && g.chef) { d.chef = g.chef; d.chefName = g.chefName; }
    const roh = b64(enc.encode(JSON.stringify(d))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return `https://bernhardschwab0-max.github.io/${APP_PFADE[zielApp]}/#zugang=${roh}`;
  }

  // ---------- Online-Speicher ----------
  function kopf(mitInhalt) {
    const h = mitInhalt ? { 'Content-Type': 'application/json' } : {};
    if (!sitzung) return h;
    if (sitzung.art === 'master') h['X-Master-Key'] = sitzung.key; else h['X-Access-Key'] = sitzung.key;
    return h;
  }
  async function antwort(res, was) {
    if (res.status === 401 || res.status === 403) throw new Error(`${was}: keine Berechtigung`);
    if (res.status === 404) throw new Error(`${was}: Speicher nicht gefunden`);
    if (!res.ok) throw new Error(`${was}: Fehler ${res.status}`);
    return res.json();
  }
  async function binLesen(id, eigenerKopf) {
    const res = await fetch(`${API}/b/${encodeURIComponent(id)}/latest`, { headers: eigenerKopf || kopf(), cache: 'no-store' });
    const j = await antwort(res, 'Lesen');
    return j && j.record !== undefined ? j.record : j;
  }
  async function binSchreiben(id, daten) {
    const res = await fetch(`${API}/b/${encodeURIComponent(id)}`, { method: 'PUT', headers: { ...kopf(true), 'X-Bin-Versioning': 'false' }, body: JSON.stringify(daten) });
    return antwort(res, 'Speichern');
  }

  // ---------- Team (Mitarbeiterliste) ----------
  const teamCache = () => lade(LS_TEAM, null);
  function teamCacheSetzen(team) {
    if (!team) return;
    speichere(LS_TEAM, {
      zeit: Date.now(),
      chefName: team.chefName || 'Chef',
      mitarbeiter: (team.mitarbeiter || []).map((m) => ({ id: m.id, name: m.name, salt: m.salt, hash: m.hash, aktiv: m.aktiv !== false })),
    });
    const g = geraet();
    const aend = {};
    if (team.chefName && team.chefName !== g.chefName) aend.chefName = team.chefName;
    if (team.mk && team.mk !== g.mk) aend.mk = team.mk;
    if (Object.keys(aend).length) geraetSetzen(aend);
  }
  async function teamHolen(mitKopf) {
    const g = geraet();
    if (!g.teamBin) return null;
    const team = await binLesen(g.teamBin, mitKopf);
    teamCacheSetzen(team);
    return team;
  }
  async function mitarbeiterZuCode(code) {
    const g = geraet();
    const suchen = async (cache) => {
      for (const m of (cache && cache.mitarbeiter) || []) {
        if (m.aktiv !== false && m.salt && m.hash && (await codeHash(m.salt, code)) === m.hash) return m;
      }
      return null;
    };
    let treffer = await suchen(teamCache());
    // Nicht gefunden: vielleicht neu angelegt → Liste frisch holen (mit dem Mitarbeiter-Schlüssel)
    if (!treffer && g.teamBin && g.mk) {
      try { await teamHolen({ 'X-Access-Key': g.mk }); treffer = await suchen(teamCache()); } catch (e) {}
    }
    return treffer;
  }

  // ---------- Sitzung ----------
  function sitzungLaden() {
    try { const s = JSON.parse(sessionStorage.getItem(SS_SITZUNG) || 'null'); return s && s.key && s.rolle ? s : null; } catch (e) { return null; }
  }
  function sitzungSetzen(s) {
    sitzung = s;
    try { if (s) sessionStorage.setItem(SS_SITZUNG, JSON.stringify(s)); else sessionStorage.removeItem(SS_SITZUNG); } catch (e) {}
  }
  function abmelden() {
    senden(true);
    sitzungSetzen(null);
    setTimeout(() => location.reload(), 300);
  }

  // ---------- Protokoll ----------
  function log(text) {
    if (!sitzung || !text) return;
    const q = lade(LS_QUEUE, []) || [];
    q.push({ id: neueId(), z: Date.now(), w: sitzung.id, n: sitzung.name, r: sitzung.rolle, a: app, t: String(text).slice(0, 300) });
    speichere(LS_QUEUE, q.slice(-1000));
    planeSenden();
  }
  let sendTimer = null, sendet = false, letztesSenden = 0;
  function planeSenden(sofort) {
    clearTimeout(sendTimer);
    const q = lade(LS_QUEUE, []) || [];
    if (!q.length) return;
    // gebündelt schicken (spart Zugriffe): höchstens alle 90 Sekunden, bei vielen Einträgen gleich
    const warte = sofort || q.length >= 20 ? 1500 : Math.max(8000, 90000 - (Date.now() - letztesSenden));
    sendTimer = setTimeout(() => senden(), warte);
  }
  async function senden() {
    const g = geraet();
    if (sendet || !sitzung || !g.teamBin) return;
    const q = lade(LS_QUEUE, []) || [];
    if (!q.length) return;
    sendet = true;
    try {
      const team = await binLesen(g.teamBin);
      const da = new Set((team.protokoll || []).map((e) => e.id));
      const grenze = Date.now() - PROTOKOLL_TAGE * 864e5;
      const liste = (team.protokoll || []).concat(q.filter((e) => !da.has(e.id)))
        .filter((e) => e.z >= grenze)
        .sort((a, b) => a.z - b.z)
        .slice(-PROTOKOLL_MAX);
      await binSchreiben(g.teamBin, { ...team, protokoll: liste });
      teamCacheSetzen(team);
      const weg = new Set(q.map((e) => e.id));
      speichere(LS_QUEUE, (lade(LS_QUEUE, []) || []).filter((e) => !weg.has(e.id)));
      letztesSenden = Date.now();
    } catch (e) {
      // ohne Internet o. ä.: bleibt auf dem Gerät und geht später mit
    } finally {
      sendet = false;
    }
    if ((lade(LS_QUEUE, []) || []).length) planeSenden();
  }
  const offeneEintraege = () => (lade(LS_QUEUE, []) || []).length;

  // ---------- Team-Verwaltung (nur Chef, für die Bestell-App) ----------
  async function teamAnlegen() {
    if (!istChef()) throw new Error('Nur mit Chef-Code');
    const team = { art: 'team', version: 1, chefName: geraet().chefName || 'Chef', mitarbeiter: [], protokoll: [] };
    const res = await fetch(`${API}/b`, { method: 'POST', headers: { ...kopf(true), 'X-Bin-Name': 'team', 'X-Bin-Private': 'true' }, body: JSON.stringify(team) });
    const j = await antwort(res, 'Team-Speicher anlegen');
    const id = j && j.metadata && j.metadata.id;
    if (!id) throw new Error('Team-Speicher: keine Nummer erhalten');
    geraetSetzen({ teamBin: id });
    teamCacheSetzen(team);
    return id;
  }
  async function mitarbeiterSchluesselAnlegen() {
    if (!istChef()) throw new Error('Nur mit Chef-Code');
    const res = await fetch(`${API}/a`, {
      method: 'POST',
      headers: { ...kopf(true), 'X-Key-Name': 'mitarbeiter' },
      body: JSON.stringify({ bins: { read: true, update: true, delete: false, create: false } }),
    });
    const j = await antwort(res, 'Mitarbeiter-Schlüssel anlegen');
    if (!j || !j.accessKey) throw new Error('Mitarbeiter-Schlüssel: keinen Schlüssel erhalten');
    geraetSetzen({ mk: j.accessKey });
    return { mk: j.accessKey, mkId: j.accessKeyId };
  }
  // Einmalig: Mitarbeiter-Schlüssel und Team-Speicher anlegen (Schlüssel steht im Team-Speicher, damit jedes
  // Chef-Gerät Mitarbeiter-Geräte einrichten kann)
  async function teamEinrichten() {
    if (!istChef()) throw new Error('Nur mit Chef-Code');
    let g = geraet();
    if (!g.mk) await mitarbeiterSchluesselAnlegen();
    if (!geraet().teamBin) await teamAnlegen();
    g = geraet();
    return teamAendern((t) => ({ ...t, mk: g.mk }));
  }
  async function teamAendern(fn) {
    if (!istChef()) throw new Error('Nur mit Chef-Code');
    const g = geraet();
    const team = await binLesen(g.teamBin);
    const neu = await fn({ ...team, mitarbeiter: [...(team.mitarbeiter || [])] });
    await binSchreiben(g.teamBin, neu);
    teamCacheSetzen(neu);
    return neu;
  }
  async function codeVergeben(team, code, ausserId) {
    for (const m of team.mitarbeiter || []) {
      if (m.id !== ausserId && m.salt && (await codeHash(m.salt, code)) === m.hash) return true;
    }
    return false;
  }
  async function codeDaten(code) {
    const salt = b64(zufall(12));
    return { salt, hash: await codeHash(salt, code) };
  }
  async function chefCodeAendern(alterCode, neuerCode) {
    const g = geraet();
    const key = await entschluesseln(g.chef, alterCode);
    geraetSetzen({ chef: await verschluesseln(key, neuerCode) });
  }

  const istChef = () => !!(sitzung && sitzung.rolle === 'chef');

  // ---------- Oberfläche (Code-Eingabe usw.) ----------
  function stileEinfuegen() {
    if (document.getElementById('zugang-stil')) return;
    const st = document.createElement('style');
    st.id = 'zugang-stil';
    st.textContent = `
      .zg-hinter{position:fixed;inset:0;z-index:2147483000;background:#FAF3E7;display:flex;align-items:flex-start;justify-content:center;overflow:auto;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;color:#2E2118;padding:max(24px,env(safe-area-inset-top)) 16px 24px;-webkit-tap-highlight-color:transparent}
      .zg-box{width:100%;max-width:380px;text-align:center}
      .zg-logo{font-family:Georgia,serif;font-weight:700;letter-spacing:.04em;color:#3B2A1E;font-size:20px;margin-top:8px}
      .zg-app{font-size:13px;color:#8C7C68;margin-top:2px;letter-spacing:.06em;text-transform:uppercase;font-weight:700}
      .zg-titel{font-family:Georgia,serif;font-size:24px;font-weight:700;margin:22px 0 6px}
      .zg-text{font-size:15px;color:#8C7C68;line-height:1.45;margin:0 0 14px}
      .zg-punkte{display:flex;justify-content:center;gap:12px;height:24px;margin:14px 0 6px}
      .zg-punkte i{width:16px;height:16px;border-radius:8px;border:2px solid #C4622D;display:block}
      .zg-punkte i.voll{background:#C4622D}
      .zg-fehler{min-height:22px;color:#B3401D;font-weight:600;font-size:15px}
      .zg-tasten{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:10px auto 0;max-width:300px}
      .zg-tasten button{height:66px;border-radius:18px;border:1px solid #EADFC9;background:#fff;font-size:28px;font-weight:600;color:#2E2118;cursor:pointer;font-family:inherit}
      .zg-tasten button:active{background:#F9E7D8}
      .zg-tasten button.zg-ok{background:#C4622D;color:#fff;border-color:#C4622D;font-size:20px}
      .zg-tasten button.zg-klein{font-size:18px;color:#8C7C68}
      .zg-link{background:none;border:0;color:#8C7C68;font-size:14px;margin-top:22px;text-decoration:underline;cursor:pointer;font-family:inherit}
      .zg-feld{width:100%;box-sizing:border-box;border:2px solid #EADFC9;border-radius:12px;padding:12px;font-size:15px;background:#fff;font-family:monospace;margin-top:6px}
      .zg-feld:focus{outline:0;border-color:#C4622D}
      .zg-knopf{width:100%;margin-top:12px;min-height:54px;border-radius:14px;border:0;background:#C4622D;color:#fff;font-size:18px;font-weight:700;cursor:pointer;font-family:inherit}
      .zg-knopf.zg-zweit{background:#fff;color:#C4622D;border:2px solid #C4622D}
      .zg-knopf:disabled{opacity:.5}
      .zg-hinweis{font-size:13px;color:#8C7C68;margin-top:10px;line-height:1.4}
      .zg-wer{position:fixed;z-index:2147482000;right:10px;bottom:calc(10px + env(safe-area-inset-bottom));display:flex;align-items:center;gap:6px;background:#3B2A1E;color:#FFF8EE;border-radius:999px;padding:6px 6px 6px 12px;font:600 13px -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;box-shadow:0 4px 14px rgba(0,0,0,.2)}
      .zg-wer button{background:#C4622D;color:#fff;border:0;border-radius:999px;padding:5px 10px;font:inherit;cursor:pointer}
      @media print{.zg-wer{display:none}}
    `;
    document.head.appendChild(st);
  }

  function rahmen(inhalt) {
    const el = document.createElement('div');
    el.className = 'zg-hinter';
    el.innerHTML = `<div class="zg-box"><div class="zg-logo">BÖRNI´S BACKSTUBE</div><div class="zg-app">${esc(APP_NAMEN[app] || '')}</div>${inhalt}</div>`;
    document.body.appendChild(el);
    return el;
  }

  // Ziffernblock; pruefe(code) liefert true (fertig), 'weiter' (mehr Ziffern) oder einen Fehlertext
  function ziffernblock({ titel, text, minLaenge = 4, maxLaenge = 10, autoBei, pruefe, unten }) {
    return new Promise((fertig) => {
      const el = rahmen(`
        <div class="zg-titel">${esc(titel)}</div>
        <p class="zg-text">${text}</p>
        <div class="zg-punkte"></div>
        <div class="zg-fehler"></div>
        <div class="zg-tasten">
          ${[1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => `<button data-z="${n}">${n}</button>`).join('')}
          <button class="zg-klein" data-z="weg" aria-label="Löschen">⌫</button>
          <button data-z="0">0</button>
          <button class="zg-ok" data-z="ok">OK</button>
        </div>
        ${unten || ''}`);
      const punkte = el.querySelector('.zg-punkte');
      const fehler = el.querySelector('.zg-fehler');
      let code = '';
      let beschaeftigt = false;
      let fehlversuche = 0;
      let gesperrtBis = 0;
      const zeigen = () => {
        const n = Math.max(code.length, minLaenge);
        punkte.innerHTML = Array.from({ length: n }, (_, i) => `<i class="${i < code.length ? 'voll' : ''}"></i>`).join('');
      };
      const versuchen = async (automatisch) => {
        if (beschaeftigt) return;
        if (Date.now() < gesperrtBis) { fehler.textContent = 'Bitte kurz warten …'; return; }
        if (code.length < minLaenge) { if (!automatisch) fehler.textContent = `Mindestens ${minLaenge} Ziffern`; return; }
        beschaeftigt = true;
        fehler.textContent = '…';
        let r;
        try { r = await pruefe(code); } catch (e) { r = e.message || 'Fehler'; }
        beschaeftigt = false;
        if (r === true) { el.remove(); fertig(code); return; }
        if (r === 'weiter') { fehler.textContent = ''; return; }
        fehlversuche++;
        if (fehlversuche >= 5) { gesperrtBis = Date.now() + 30000; fehlversuche = 0; }
        fehler.textContent = r || 'Falscher Code';
        code = '';
        zeigen();
      };
      el.addEventListener('click', (ev) => {
        const b = ev.target.closest('[data-z]');
        if (!b) return;
        const z = b.dataset.z;
        if (z === 'weg') { code = code.slice(0, -1); fehler.textContent = ''; }
        else if (z === 'ok') { versuchen(false); return; }
        else if (code.length < maxLaenge) { code += z; fehler.textContent = ''; }
        zeigen();
        if (autoBei && code.length === autoBei) versuchen(true);
      });
      const taste = (ev) => {
        if (!document.body.contains(el)) { document.removeEventListener('keydown', taste); return; }
        if (/^[0-9]$/.test(ev.key) && code.length < maxLaenge) { code += ev.key; fehler.textContent = ''; zeigen(); if (autoBei && code.length === autoBei) versuchen(true); }
        else if (ev.key === 'Backspace') { code = code.slice(0, -1); zeigen(); }
        else if (ev.key === 'Enter') versuchen(false);
      };
      document.addEventListener('keydown', taste);
      el.addEventListener('click', (ev) => { const a = ev.target.closest('[data-aktion]'); if (a && typeof unten === 'string') { el.remove(); fertig({ aktion: a.dataset.aktion }); } });
      zeigen();
    });
  }

  async function chefCodeFestlegen(key) {
    let erster = '';
    await ziffernblock({
      titel: 'Chef-Code festlegen',
      text: 'Ab jetzt schützt dein Chef-Code den Zugang auf diesem Gerät. Wähle <b>mindestens 6 Ziffern</b> und merk ihn dir gut – auf allen deinen Geräten am besten denselben.',
      minLaenge: 6,
      pruefe: async (c) => { erster = c; return true; },
    });
    await ziffernblock({
      titel: 'Chef-Code wiederholen',
      text: 'Bitte denselben Code noch einmal eingeben.',
      minLaenge: 6,
      pruefe: async (c) => (c === erster ? true : 'Die Codes sind nicht gleich – nochmal'),
    });
    geraetSetzen({ chef: await verschluesseln(key, erster) });
    altSchluesselEntfernen();
    return erster;
  }

  function einrichtenAnzeigen() {
    return new Promise((fertig) => {
      const el = rahmen(`
        <div class="zg-titel">Gerät einrichten</div>
        <p class="zg-text">Scanne den QR-Code aus der Bestell-App (Chef: Einstellungen → Mitarbeiter &amp; Protokoll → Gerät einrichten) oder füge den Link hier ein.</p>
        <textarea class="zg-feld" id="zg-link" rows="3" placeholder="https://…#zugang=…" autocomplete="off" autocapitalize="off" spellcheck="false"></textarea>
        <button class="zg-knopf" id="zg-los">Einrichten</button>
        <div class="zg-fehler" id="zg-f" style="margin-top:8px"></div>
        <details style="margin-top:18px;text-align:left"><summary class="zg-hinweis" style="cursor:pointer">Chef: mit dem jsonbin-Schlüssel einrichten</summary>
          <input class="zg-feld" id="zg-key" placeholder="jsonbin-Schlüssel (X-Master-Key)" autocomplete="off" autocapitalize="off" spellcheck="false">
          <input class="zg-feld" id="zg-lager" placeholder="Speicher-Nr. der Lager-App" autocomplete="off" autocapitalize="off" spellcheck="false">
          <input class="zg-feld" id="zg-bestell" placeholder="Speicher-Nr. der Bestell-App (falls bekannt)" autocomplete="off" autocapitalize="off" spellcheck="false">
          <button class="zg-knopf zg-zweit" id="zg-chef">Als Chef einrichten</button>
        </details>`);
      el.querySelector('#zg-los').addEventListener('click', () => {
        const r = linkLesen(el.querySelector('#zg-link').value);
        if (!r) { el.querySelector('#zg-f').textContent = 'Der Link passt nicht – bitte den ganzen Link einfügen'; return; }
        el.remove();
        fertig(r);
      });
      el.querySelector('#zg-chef').addEventListener('click', () => {
        const key = el.querySelector('#zg-key').value.trim(), lagerBin = el.querySelector('#zg-lager').value.trim();
        const bestellBin = el.querySelector('#zg-bestell').value.trim();
        if (!key || !lagerBin) { el.querySelector('#zg-f').textContent = 'Schlüssel und Lager-Speicher-Nr. eintragen'; return; }
        el.remove();
        fertig({ alt: { key, lagerBin, bestellBin: bestellBin || undefined } });
      });
    });
  }

  async function linkUebernehmen(r) {
    if (!r) return;
    if (r.neu) {
      const d = r.neu;
      const g = geraet();
      if (g.lagerBin && d.lagerBin && g.lagerBin !== d.lagerBin &&
        !confirm('Achtung: Dieser Link verbindet die App mit einem ANDEREN Online-Speicher.\n\nNur bestätigen, wenn der Link von deinem eigenen Gerät stammt. Fortfahren?')) return;
      const aend = { lagerBin: d.lagerBin };
      if (d.bestellBin) aend.bestellBin = d.bestellBin;
      if (d.teamBin) aend.teamBin = d.teamBin;
      if (d.mk) aend.mk = d.mk;
      if (d.chef) { aend.chef = d.chef; if (d.chefName) aend.chefName = d.chefName; }
      geraetSetzen(aend);
    } else if (r.alt) {
      // alter Link / Chef-Einrichtung mit Generalschlüssel: gleich verschlüsseln
      geraetSetzen({ lagerBin: r.alt.lagerBin, ...(r.alt.bestellBin ? { bestellBin: r.alt.bestellBin } : {}) });
      await chefCodeFestlegen(r.alt.key);
    }
  }

  async function anmelden() {
    const g = geraet();
    // Auf Geräten mit Chef-Zugang (z. B. gemeinsames Tablet) nicht nach 4 Ziffern automatisch prüfen –
    // sonst könnte der Chef-Code mit dem Code eines Mitarbeiters beginnen. Dort immer mit OK bestätigen.
    const auto = g.chef || nurChef ? 0 : 4;
    const ergebnis = await ziffernblock({
      titel: 'Anmelden',
      text: nurChef
        ? 'Diese App ist nur für den Chef. Bitte den Chef-Code eingeben und OK tippen.'
        : g.chef ? 'Mitarbeiter: dein 4-stelliger Code, dann OK.<br>Chef: dein Chef-Code, dann OK.' : 'Bitte deinen 4-stelligen Code eingeben.',
      minLaenge: 4,
      autoBei: auto,
      unten: '<button class="zg-link" data-aktion="einrichten">Gerät neu einrichten</button>',
      pruefe: async (code) => {
        if (code.length === 4) {
          if (nurChef) return 'Diese App ist nur für den Chef';
          const m = await mitarbeiterZuCode(code);
          if (m) {
            const mk = geraet().mk;
            if (!mk) return 'Dieses Gerät hat keinen Mitarbeiter-Zugang – bitte vom Chef einrichten lassen';
            sitzungSetzen({ rolle: 'mitarbeiter', id: m.id, name: m.name, key: mk, art: 'access', seit: Date.now() });
            return true;
          }
          return 'Code unbekannt';
        }
        if (code.length >= 6 && g.chef) {
          try {
            const key = await entschluesseln(g.chef, code);
            sitzungSetzen({ rolle: 'chef', id: 'chef', name: geraet().chefName || 'Chef', key, art: 'master', seit: Date.now() });
            return true;
          } catch (e) {
            return 'Falscher Code';
          }
        }
        return g.chef ? 'Falscher Code' : 'Code unbekannt';
      },
    });
    if (ergebnis && ergebnis.aktion === 'einrichten') {
      const r = await einrichtenAnzeigen();
      await linkUebernehmen(r);
      return anmelden();
    }
    return sitzung;
  }

  // Wer ist angemeldet – kleine Anzeige mit Abmelden (für gemeinsame Geräte)
  function werAnzeigen() {
    if (!sitzung || document.getElementById('zg-wer')) return;
    const el = document.createElement('div');
    el.id = 'zg-wer';
    el.className = 'zg-wer';
    el.innerHTML = `<span>👤 ${esc(sitzung.name)}</span><button type="button">Abmelden</button>`;
    el.querySelector('button').addEventListener('click', () => abmelden());
    document.body.appendChild(el);
  }

  // Nach einer Pause neu anmelden; Protokoll beim Verlassen losschicken
  function beobachten() {
    let weg = 0;
    let zuletztAktiv = Date.now();
    const gemeinsam = () => !!geraet().mk; // Gerät mit Mitarbeiter-Zugang (z. B. Firmen-Tablet)
    const sperren = () => {
      if (!sitzung) return;
      senden();
      sitzungSetzen(null);
      location.reload();
    };
    ['pointerdown', 'keydown', 'touchstart'].forEach((art) =>
      document.addEventListener(art, () => { zuletztAktiv = Date.now(); }, { passive: true, capture: true }));
    setInterval(() => {
      if (sitzung && gemeinsam() && document.visibilityState === 'visible' && Date.now() - zuletztAktiv > UNTAETIG_GEMEINSAM_MIN * 60000) sperren();
    }, 30000);
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') { weg = Date.now(); senden(); return; }
      const grenze = (gemeinsam() ? HINTERGRUND_GEMEINSAM_MIN : HINTERGRUND_MIN) * 60000;
      if (weg && sitzung && Date.now() - weg > grenze) { sperren(); return; }
      zuletztAktiv = Date.now();
      planeSenden();
    });
    window.addEventListener('online', () => planeSenden(true));
  }

  // Chef-Gerät ohne Team-Speicher-Nr.: im Konto suchen (einmal, danach gemerkt)
  async function teamSuchen() {
    const g = geraet();
    if (g.teamBin || !istChef() || g.teamGesucht === new Date().toISOString().slice(0, 10)) return;
    geraetSetzen({ teamGesucht: new Date().toISOString().slice(0, 10) });
    try {
      let letzte = '';
      for (let i = 0; i < 5; i++) {
        const res = await fetch(`${API}/c/uncategorized/bins${letzte ? '/' + letzte : ''}`, { headers: kopf() });
        if (!res.ok) break;
        const liste = await res.json();
        if (!Array.isArray(liste) || !liste.length) break;
        for (const b of liste) {
          const id = b.record;
          if (!id || id === g.lagerBin || id === g.bestellBin) continue;
          if (b.snippetMeta && b.snippetMeta.name && b.snippetMeta.name !== 'team') continue;
          try {
            const rec = await binLesen(id);
            if (rec && rec.art === 'team') { geraetSetzen({ teamBin: id }); teamCacheSetzen(rec); return; }
          } catch (e) {}
        }
        if (liste.length < 10) break;
        letzte = liste[liste.length - 1].record;
      }
    } catch (e) {}
  }

  function teamBinSetzen(id) {
    if (id && id !== geraet().teamBin) geraetSetzen({ teamBin: id });
  }
  // Speicher-Nummern ändern (z. B. nach dem Zusammenführen zweier Bestell-Speicher)
  function speicherSetzen(aend) {
    const a = {};
    if (aend && aend.lagerBin) a.lagerBin = aend.lagerBin;
    if (aend && aend.bestellBin) a.bestellBin = aend.bestellBin;
    geraetSetzen(a);
  }
  // Gerät (neu) einrichten: Link / QR-Code oder Chef-Schlüssel, danach neu laden
  async function neuEinrichten() {
    stileEinfuegen();
    await linkUebernehmen(await einrichtenAnzeigen());
    location.reload();
  }

  // ---------- Start ----------
  // opts: { app: 'lager'|'bestell'|'rezept', nurChef: bool }
  async function start(opts) {
    app = opts.app;
    nurChef = !!opts.nurChef;
    stileEinfuegen();
    beobachten();

    // Einrichtungs-Link in der Adresse?
    const r = linkLesen(location.hash);
    if (r) {
      history.replaceState(history.state, '', location.pathname + location.search);
      await linkUebernehmen(r);
    }

    // Laufende Sitzung (z. B. nach dem Neuladen)
    const s = sitzungLaden();
    if (s && (!nurChef || s.rolle === 'chef')) {
      sitzung = s;
    } else {
      let g = geraet();
      // Erster Start nach dem Umbau: Generalschlüssel liegt noch im Klartext → Chef-Code festlegen
      const alt = altKonfig();
      if (!g.chef && alt.key) {
        geraetSetzen({ lagerBin: g.lagerBin || alt.lagerBin, bestellBin: g.bestellBin || alt.bestellBin });
        await chefCodeFestlegen(alt.key);
        g = geraet();
      } else if (g.chef && alt.key) {
        altSchluesselEntfernen();
      }
      while (!g.chef && !g.mk) {
        await linkUebernehmen(await einrichtenAnzeigen());
        g = geraet();
      }
      await anmelden();
      log(`Anmeldung (${APP_NAMEN[app]})`);
    }
    if (opts.chip) werAnzeigen();
    await teamSuchen(); // nur Chef ohne bekannte Team-Speicher-Nr., höchstens einmal am Tag
    planeSenden();
    return sitzung;
  }

  return {
    VERSION,
    start,
    get sitzung() { return sitzung; },
    istChef,
    kopf,
    geraet,
    log,
    senden: () => senden(),
    offeneEintraege,
    abmelden,
    linkBauen,
    teamBinSetzen,
    speicherSetzen,
    neuEinrichten,
    teamHolen,
    teamAnlegen,
    teamEinrichten,
    teamAendern,
    mitarbeiterSchluesselAnlegen,
    codeVergeben,
    codeDaten,
    chefCodeAendern,
    APP_NAMEN,
  };
})();

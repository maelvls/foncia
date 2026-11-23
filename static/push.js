"use strict";

// The page "Notifications" (Web Push: push.go, sw.js). Only « Activer » asks
// the browser for the permission.

(() => {
  const box = document.getElementById("push");
  const state = document.getElementById("push-state");
  const base = box.dataset.base || ""; // The base path of the site.
  const P = { info: null, sub: null, error: "" };

  const supported = () => "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
  const isIOS = () => /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);

  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else if (typeof v === "boolean") e[k] = v;
      else if (v != null) e.setAttribute(k, v);
    }
    e.append(...children.flat().filter((c) => c != null));
    return e;
  }
  const note = (text, cls) => el("p", { class: "push-note " + (cls || "muted") }, text);

  function b64urlBytes(s) {
    const b = atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "="));
    return Uint8Array.from(b, (c) => c.charCodeAt(0));
  }

  function sameKey(buf, key) {
    if (!buf) return true; // not told: assume it's ours
    const a = new Uint8Array(buf);
    return a.length === key.length && a.every((v, i) => v === key[i]);
  }

  function deviceName(ua) {
    const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android"
      : /Mac OS X/.test(ua) ? "Mac" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "Appareil";
    const br = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome"
      : /Version\/.*Safari\//.test(ua) ? "Safari" : "";
    return br ? os + " · " + br : os;
  }

  let msg = null; // what the last action said
  function say(text, ok) {
    msg = { text, ok };
    render();
  }

  // call posts with the button showing it's waiting, and says how it went.
  async function call(button, path, body) {
    if (button) button.disabled = true;
    try {
      const r = await fetch(base + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!r.ok) throw new Error(r.status + " " + r.statusText);
      const d = await r.json();
      say(d.message, d.ok);
      return d.ok;
    } catch (e) {
      say("Erreur : " + e.message, false);
      return false;
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function load() {
    try {
      const reg = await navigator.serviceWorker.getRegistration(base + "/");
      P.sub = reg ? await reg.pushManager.getSubscription() : null;
      if (P.sub) navigator.serviceWorker.register(base + "/sw.js", { scope: base + "/" }).catch(() => {}); // to update it
    } catch (e) { /* no worker: not subscribed */ }
    try {
      const r = await fetch(base + "/api/push");
      if (!r.ok) throw new Error(r.status + " " + r.statusText);
      P.info = await r.json();
      P.error = "";
    } catch (e) {
      P.error = e.message;
    }
    render();
  }

  async function enable(e) {
    const b = e.currentTarget;
    b.disabled = true;
    try {
      // The permission first, straight from the click: Safari wants it so.
      if (await Notification.requestPermission() !== "granted") {
        say("Notifications refusées : autorisez-les dans les réglages du navigateur.", false);
        return;
      }
      await navigator.serviceWorker.register(base + "/sw.js", { scope: base + "/" });
      const reg = await navigator.serviceWorker.ready;
      const key = b64urlBytes(P.info.key);
      let sub = await reg.pushManager.getSubscription();
      // Subscribed with another key (the server lost its own): start again.
      if (sub && !sameKey(sub.options.applicationServerKey, key)) { await sub.unsubscribe(); sub = null; }
      if (!sub) sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
      P.sub = sub;
      await call(null, "/api/push/subscribe", { subscription: sub.toJSON() });
    } catch (err) {
      say("Notifications : " + err.message, false);
    } finally {
      b.disabled = false;
      load();
    }
  }

  async function disable(e) {
    const b = e.currentTarget;
    const endpoint = P.sub.endpoint;
    try { await P.sub.unsubscribe(); } catch (err) { /* gone already */ }
    P.sub = null;
    await call(b, "/api/push/unsubscribe", { endpoint });
    load();
  }

  async function kind(mine, id, input) {
    const events = { ...(mine.events || {}), [id]: input.checked };
    input.disabled = true;
    if (await call(null, "/api/push/subscribe", { subscription: P.sub.toJSON(), events })) mine.events = events;
    else input.checked = !input.checked;
    input.disabled = false;
  }

  function render() {
    state.textContent = "";
    if (!supported()) {
      box.replaceChildren(note(isIOS()
        ? "Sur un iPhone ou un iPad, installez d'abord le site sur l'écran d'accueil (bouton Partager, puis « Sur l'écran d'accueil »), ouvrez-le depuis là et revenez sur cette page."
        : "Ce navigateur ne sait pas recevoir de notifications."));
      return;
    }
    if (!P.info) {
      box.replaceChildren(note(P.error ? "Erreur : " + P.error : "Chargement…"));
      return;
    }
    const devices = P.info.devices || [];
    const mine = P.sub && devices.find((d) => d.endpoint === P.sub.endpoint);
    const allowed = Notification.permission !== "denied";
    const parts = [];
    if (mine) {
      state.replaceChildren(el("span", { class: "badge levee" }, "activées sur cet appareil"));
      if (Notification.permission !== "granted") parts.push(note("Le navigateur bloque les notifications de ce site : autorisez-les dans ses réglages.", "alerte"));
      parts.push(el("div", { class: "push-kinds" }, P.info.kinds.map((k) => el("label", {},
        el("input", { type: "checkbox", checked: !mine.events || mine.events[k.id] !== false, onchange: (e) => kind(mine, k.id, e.target) }),
        " " + k.label))));
      parts.push(el("div", { class: "barre-actions" },
        el("button", { type: "button", class: "btn secondaire", onclick: (e) => call(e.currentTarget, "/api/push/test", {}) }, "Envoyer un test"),
        el("button", { type: "button", class: "btn secondaire", onclick: disable }, "Désactiver sur cet appareil")));
    } else {
      if (!allowed) parts.push(note("Le navigateur bloque les notifications de ce site : autorisez-les dans ses réglages, puis revenez ici.", "alerte"));
      parts.push(el("div", { class: "barre-actions" },
        el("button", { class: "btn", type: "button", disabled: !allowed, onclick: enable }, "Activer sur cet appareil")));
    }
    if (msg) parts.push(note(msg.text, msg.ok ? "bien" : "alerte"));
    if (devices.length) {
      parts.push(el("div", { class: "push-devices" },
        el("h2", {}, "Vos appareils abonnés"),
        el("ul", {}, devices.map((d) => el("li", {},
          deviceName(d.ua) + " ",
          el("small", {}, (d === mine ? "cet appareil, " : "") + "depuis le " +
            new Date(d.created).toLocaleDateString("fr-FR", { day: "numeric", month: "long", year: "numeric" })),
          d === mine ? null : " ",
          d === mine ? null : el("button", { type: "button", class: "lien", onclick: async () => {
            await call(null, "/api/push/unsubscribe", { endpoint: d.endpoint });
            load();
          } }, "Retirer"))))));
    }
    box.replaceChildren(...parts);
  }

  if (!supported()) render();
  else load();
})();

"use strict";

// The service worker of the site, served at the root of the site (its scope):
// it only shows the server's push notifications (push.go) and opens the page
// on a click. No fetch handler, no cache.

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

// The root of the site, base path included.
const root = () => self.registration.scope;

self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (err) { d = { body: e.data.text() }; }
  // Safari cancels the subscription of a worker that shows nothing.
  e.waitUntil(self.registration.showNotification(d.title || "Terra Nostra 2", {
    body: d.body || "",
    icon: new URL("icon.png", root()).href,
    lang: "fr",
    data: { url: d.url || "" },
  }));
});

// A click brings the page to the right place if it's open, else opens it.
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = new URL((e.notification.data && e.notification.data.url) || root(), self.location.origin).href;
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    const w = wins.find((c) => c.url.startsWith(root()));
    if (!w) return self.clients.openWindow(url);
    await w.focus();
    try { await w.navigate(url); } catch (err) { /* not controlled by this worker */ }
  })());
});

/* WhatHappened service worker. It does one thing: receive a chat shared from WhatsApp on Android
   and hand it to the page. It caches nothing else and sends nothing anywhere. */
self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (e) { e.waitUntil(self.clients.claim()); });
self.addEventListener("fetch", function (e) {
  var url = new URL(e.request.url);
  if (e.request.method !== "POST" || !/\/share$/.test(url.pathname)) { return; }
  e.respondWith((async function () {
    try {
      var form = await e.request.formData(), files = form.getAll("chat"), cache = await caches.open("wh-shared"), n = 0;
      for (var i = 0; i < files.length; i++) {
        var f = files[i];
        if (!f || !f.arrayBuffer) { continue; }
        await cache.put("shared-" + n, new Response(f, { headers: { "X-Name": encodeURIComponent(f.name || "chat.zip"), "X-Date": String(f.lastModified || Date.now()) } }));
        n++;
      }
      await cache.put("shared-count", new Response(String(n)));
    } catch (err) {}
    return Response.redirect("./?shared=1", 303);
  })());
});

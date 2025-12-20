const APP_SHELL_FILES = ["./", "./index.html", "./main.min.js", "sw.min.js"];
let pendingNavData = null;
const clientSessionStore = new Map();
const handleCache = new Map();
const manifestCache = new Map();
const ruleCache = new Map();

const RFS_PREFIX = "rfs";
const SYSTEM_FILE = "rfs_system.json";
const CACHE_NAME = "fc";
const NETWORK_ALLOWLIST_PREFIXES = [];
const FULL_APP_SHELL_URLS = APP_SHELL_FILES.map(
  (file) => new URL(file, self.location.href).href
);

const STORE_ENTRY_TTL = 600000;
const basePath = new URL("./", self.location).pathname;
const virtualPathPrefix = basePath + "n/";

// A big ol' list of common mime types. Customize if needed.
function getMimeType(filePath) {
  const ext = filePath.split(".").pop().toLowerCase();
  const mimeTypes = {
    html: "text/html",
    htm: "text/html",
    css: "text/css",
    js: "text/javascript",
    mjs: "text/javascript",
    cjs: "text/javascript",
    jsx: "text/javascript",
    ts: "text/javascript",
    tsx: "text/javascript",
    json: "application/json",
    jsonld: "application/ld+json",
    xml: "application/xml",
    svg: "image/svg+xml",
    txt: "text/plain",
    md: "text/markdown",
    csv: "text/csv",
    webmanifest: "application/manifest+json",
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    gif: "image/gif",
    webp: "image/webp",
    ico: "image/x-icon",
    avif: "image/avif",
    bmp: "image/bmp",
    woff: "font/woff",
    woff2: "font/woff2",
    ttf: "font/ttf",
    otf: "font/otf",
    eot: "application/vnd.ms-fontobject",
    mp3: "audio/mpeg",
    wav: "audio/wav",
    ogg: "audio/ogg",
    m4a: "audio/mp4",
    mp4: "video/mp4",
    webm: "video/webm",
    ogv: "video/ogg",
    vtt: "text/vtt",
    wasm: "application/wasm",
    pdf: "application/pdf",
    zip: "application/zip",
    rar: "application/x-rar-compressed",
    "7z": "application/x-7z-compressed",
    tar: "application/x-tar",
    gz: "application/gzip",
    bin: "application/octet-stream",
    dat: "application/octet-stream",
  };
  return mimeTypes[ext] || "application/octet-stream";
}

let registryCache = null;
let _opfsRoot = null;
async function getOpfsRoot() {
  if (!_opfsRoot) _opfsRoot = await navigator.storage.getDirectory();
  return _opfsRoot;
}

function cleanupExpiredStores() {
  const now = Date.now();
  for (const [clientId, sessionData] of clientSessionStore.entries()) {
    if (now - sessionData.timestamp > STORE_ENTRY_TTL) {
      clientSessionStore.delete(clientId);
    }
  }
}

setInterval(cleanupExpiredStores, 60000);

function escapeRegex(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function compileRules(rulesString) {
  if (!rulesString || !rulesString.trim()) return [];

  if (ruleCache.has(rulesString)) return ruleCache.get(rulesString);

  const compiled = [];
  const lines = rulesString.trim().split(/\r?\n/);

  for (const line of lines) {
    const parts = line.split("->");
    if (parts.length < 2) continue;

    const matchPart = parts[0].trim();
    const replacePart = parts.slice(1).join("->").trim();
    const operatorMatch = matchPart.match(
      /^(.*?)\s+(\$|\$\$|\|\||\|)\s+(.*)$/s
    );

    if (!operatorMatch) continue;

    const [, fileMatch, operator, searchPattern] = operatorMatch;

    let fileRegex;
    try {
      fileRegex = new RegExp(
        fileMatch.trim() === "*" ? ".*" : fileMatch.trim()
      );
    } catch (e) {
      continue;
    }

    let searchRegex;
    try {
      switch (operator) {
        case "|":
          searchRegex = new RegExp(searchPattern, "g");
          break;
        case "$":
          searchRegex = new RegExp(escapeRegex(searchPattern), "g");
          break;
        case "||":
          searchRegex = new RegExp(searchPattern);
          break;
        case "$$":
          searchRegex = new RegExp(escapeRegex(searchPattern));
          break;
      }
    } catch (e) {
      continue;
    }

    if (searchRegex && fileRegex)
      compiled.push({ fileRegex, searchRegex, replacePart });
  }

  if (ruleCache.size > 50) ruleCache.clear();
  ruleCache.set(rulesString, compiled);

  return compiled;
}

function applyRegexRules(filePath, fileBuffer, fileType, compiledRules) {
  if (
    !/^(text\/|application\/(javascript|json|xml|x-javascript|typescript))/.test(
      fileType
    )
  )
    return fileBuffer;
  if (fileBuffer.byteLength > 10 * 1024 * 1024) return fileBuffer;

  try {
    let content = new TextDecoder().decode(fileBuffer);
    let modified = false;

    for (const rule of compiledRules) {
      if (rule.fileRegex.test(filePath)) {
        if (rule.searchRegex.test(content)) {
          content = content.replace(rule.searchRegex, rule.replacePart);
          modified = true;
        }
      }
    }
    return modified ? new TextEncoder().encode(content).buffer : fileBuffer;
  } catch (e) {
    console.error(`Error applying regex rules to ${filePath}:`, e);
    return fileBuffer;
  }
}

async function getRegistry() {
  if (registryCache) return registryCache;
  try {
    const root = await getOpfsRoot();
    const handle = await root.getFileHandle(SYSTEM_FILE);
    const file = await handle.getFile();
    registryCache = JSON.parse(await file.text());
  } catch (e) {
    registryCache = {};
  }
  return registryCache;
}

async function getCachedFileHandle(root, folderName, subDir, fileName) {
  const cacheKey = `${folderName}/${subDir}/${fileName}`;
  if (handleCache.has(cacheKey)) return handleCache.get(cacheKey);

  try {
    const rfs = await root.getDirectoryHandle(RFS_PREFIX);
    const folder = await rfs.getDirectoryHandle(folderName);
    const dir = await folder.getDirectoryHandle(subDir);
    const file = await dir.getFileHandle(fileName);

    handleCache.set(cacheKey, file);
    return file;
  } catch (e) {
    return null;
  }
}

self.addEventListener("install", async function () {
  const cache = await caches.open(CACHE_NAME);
  await Promise.all(
    APP_SHELL_FILES.map(async (url) => {
      try {
        const response = await fetch(url, { cache: "reload" });
        if (response.ok) await cache.put(url, response);
      } catch (e) {
        console.warn("Failed to cache app shell file:", url);
      }
    })
  );
  await self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    (async function () {
      await self.clients.claim();
      registryCache = null;
      try {
        await getOpfsRoot();
      } catch (err) {}
      const allClients = await self.clients.matchAll({
        includeUncontrolled: true,
      });
      for (const client of allClients) client.postMessage({ type: "SW_READY" });
    })()
  );
});

self.addEventListener("message", (e) => {
  if (!e.data) return;
  const clientId = e.source ? e.source.id : null;

  switch (e.data.type) {
    case "SET_RULES":
      const { rules, headers, key, folderName } = e.data;
      const compiledRules = compileRules(rules);

      if (!pendingNavData) pendingNavData = {};
      pendingNavData[folderName] = {
        rules,
        compiledRules,
        headers,
        key,
        timestamp: Date.now(),
      };

      if (clientId) {
        const s = clientSessionStore.get(clientId) || {};
        s.rules = rules;
        s.compiledRules = compiledRules;
        s.headers = headers;
        if (key) s.key = key;
        clientSessionStore.set(clientId, s);
      }
      if (e.ports && e.ports[0]) e.ports[0].postMessage("OK");

      setTimeout(() => {
        if (pendingNavData && pendingNavData[folderName]) {
          if (Date.now() - pendingNavData[folderName].timestamp > 5000) {
            delete pendingNavData[folderName];
          }
        }
      }, 6000);
      break;

    case "INVALIDATE_CACHE":
      registryCache = null;
      handleCache.clear();
      manifestCache.clear();
      e.waitUntil(
        (async function () {
          const allClients = await self.clients.matchAll({
            includeUncontrolled: true,
          });
          for (const client of allClients) {
            if (client.id !== clientId)
              client.postMessage({
                type: "INVALIDATE_CACHE",
                folderName: e.data.folderName,
              });
          }
        })()
      );
      break;

    case "PREPARE_FOR_IMPORT":
      registryCache = null;
      if (e.source) e.source.postMessage({ type: "IMPORT_READY" });
      break;
  }
});

function parseCustomHeaders(rulesString) {
  if (!rulesString || !rulesString.trim()) return [];
  const rules = [];
  rulesString
    .trim()
    .split("\n")
    .forEach((line) => {
      line = line.trim();
      if (line.startsWith("#") || line === "") return;
      const parts = line.split("->");
      if (parts.length < 2) return;
      const [globPart, ...headerParts] = parts;
      const glob = globPart.trim();
      const fullHeaderString = headerParts.join("->").trim();
      const colonIndex = fullHeaderString.indexOf(":");
      if (colonIndex === -1) return;

      const headerName = fullHeaderString.substring(0, colonIndex).trim();
      const headerValue = fullHeaderString.substring(colonIndex + 1).trim();

      try {
        const regex = new RegExp(
          "^" +
            glob
              .replace(/\./g, "\\.")
              .replace(/\*/g, ".*")
              .replace(/\?/g, ".") +
            "$"
        );
        rules.push({ regex, header: headerName, value: headerValue });
      } catch (e) {}
    });
  return rules;
}

function applyCustomHeaders(baseHeaders, filePath, rulesString) {
  if (!rulesString) return baseHeaders;
  const customHeaderRules = parseCustomHeaders(rulesString);
  for (const rule of customHeaderRules) {
    if (rule.regex.test(filePath)) {
      baseHeaders[rule.header] = rule.value;
    }
  }
  return baseHeaders;
}

self.addEventListener("fetch", (e) => {
  const { request, clientId } = e;
  const url = new URL(request.url);
  if (
    NETWORK_ALLOWLIST_PREFIXES.some((prefix) => url.pathname.startsWith(prefix))
  ) {
    return;
  }

  const cleanUrl = url.origin + url.pathname;

  let virtualReferrerPath = null;
  if (request.referrer && url.origin === self.location.origin) {
    try {
      const refUrl = new URL(request.referrer);
      if (refUrl.pathname.startsWith(virtualPathPrefix)) {
        const pathParts = refUrl.pathname
          .substring(virtualPathPrefix.length)
          .split("/");
        if (pathParts.length > 0 && pathParts[0]) {
          virtualReferrerPath = pathParts[0];
        }
      }
    } catch (err) {}
  }

  if (virtualReferrerPath && !url.pathname.startsWith(virtualPathPrefix)) {
    const newVirtualUrl = `${self.location.origin}${virtualPathPrefix}${virtualReferrerPath}${url.pathname}`;

    e.respondWith(
      (async () => {
        const newReq = new Request(newVirtualUrl, request);
        const response = await generateResponseForVirtualFile(newReq, clientId);

        if (response.status !== 404) return response;
        if (FULL_APP_SHELL_URLS.includes(cleanUrl)) {
          const cache = await caches.match(request);
          return cache || fetch(request);
        }

        return response;
      })()
    );
    return;
  }

  if (FULL_APP_SHELL_URLS.includes(cleanUrl)) {
    e.respondWith(
      (async () => {
        const cached = await caches.match(request);
        return cached || fetch(request);
      })()
    );
    return;
  }

  if (url.pathname.startsWith(virtualPathPrefix)) {
    e.respondWith(generateResponseForVirtualFile(request, clientId));
    return;
  }

  e.respondWith(fetch(request));
});

async function handleEncryptedRequest(
  opfsRoot,
  folderName,
  filePath,
  key,
  request
) {
  try {
    const CHUNK_SIZE = 1024 * 1024 * 4;
    const ENCRYPTED_CHUNK_OVERHEAD = 12 + 16;

    let manifest;

    if (manifestCache.has(folderName)) {
      manifest = manifestCache.get(folderName);
    } else {
      const rfs = await opfsRoot.getDirectoryHandle(RFS_PREFIX);
      const folderHandle = await rfs.getDirectoryHandle(folderName);

      const manifestHandle = await folderHandle.getFileHandle("manifest.enc");
      const manifestBuf = await (await manifestHandle.getFile()).arrayBuffer();

      const iv = manifestBuf.slice(16, 28);
      const encData = manifestBuf.slice(28);

      try {
        const dec = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          key,
          encData
        );
        manifest = JSON.parse(new TextDecoder().decode(dec));
        manifestCache.set(folderName, manifest);
      } catch (e) {
        return new Response("Password Incorrect", { status: 403 });
      }
    }

    const fileMeta = manifest[filePath] || manifest[filePath + "/index.html"];
    if (!fileMeta) return new Response("File not found", { status: 404 });

    const totalSize = fileMeta.size;

    if (totalSize === 0) {
      return new Response(new Uint8Array(0), {
        status: 200,
        headers: {
          "Content-Type": fileMeta.type || "application/octet-stream",
          "Content-Length": "0",
        },
      });
    }

    const rawFileHandle = await getCachedFileHandle(
      opfsRoot,
      folderName,
      "content",
      fileMeta.id
    );
    const rawFile = await rawFileHandle.getFile();

    const rangeHeader = request.headers.get("Range");
    let start = 0;
    let end = totalSize - 1;

    if (rangeHeader) {
      const parts = rangeHeader.replace(/bytes=/, "").split("-");
      start = parseInt(parts[0], 10);
      if (parts[1]) end = parseInt(parts[1], 10);

      if (isNaN(start)) start = 0;
      if (isNaN(end)) end = totalSize - 1;
      if (end >= totalSize) end = totalSize - 1;
    }

    if (start >= totalSize)
      return new Response(null, {
        status: 416,
        headers: { "Content-Range": `bytes */${totalSize}` },
      });

    const startChunkIdx = Math.floor(start / CHUNK_SIZE);
    const endChunkIdx = Math.floor(end / CHUNK_SIZE);

    const stream = new ReadableStream({
      async start(controller) {
        try {
          for (let i = startChunkIdx; i <= endChunkIdx; i++) {
            const isLastChunk = i * CHUNK_SIZE + CHUNK_SIZE >= totalSize;
            const plainChunkSize = isLastChunk
              ? totalSize % CHUNK_SIZE || CHUNK_SIZE
              : CHUNK_SIZE;

            const rawOffset = i * (CHUNK_SIZE + ENCRYPTED_CHUNK_OVERHEAD);
            const encChunkLen = plainChunkSize + ENCRYPTED_CHUNK_OVERHEAD;

            const slicedBlob = rawFile.slice(
              rawOffset,
              rawOffset + encChunkLen
            );
            const buf = await slicedBlob.arrayBuffer();

            if (buf.byteLength === 0) break;

            const chunkIv = buf.slice(0, 12);
            const chunkCipher = buf.slice(12);

            const plain = await crypto.subtle.decrypt(
              { name: "AES-GCM", iv: chunkIv },
              key,
              chunkCipher
            );
            const data = new Uint8Array(plain);

            const globalChunkStart = i * CHUNK_SIZE;
            const outputStart = Math.max(start, globalChunkStart);
            const outputEnd = Math.min(end + 1, globalChunkStart + data.length);

            if (outputStart < outputEnd) {
              controller.enqueue(
                data.slice(
                  outputStart - globalChunkStart,
                  outputEnd - globalChunkStart
                )
              );
            }
          }
          controller.close();
        } catch (e) {
          controller.error(e);
        }
      },
    });

    const headers = {
      "Content-Type": fileMeta.type || "application/octet-stream",
      "Content-Length": end - start + 1,
      "Content-Range": `bytes ${start}-${end}/${totalSize}`,
      "Accept-Ranges": "bytes",
      "Cache-Control": "no-store",
    };

    return new Response(stream, { status: 206, headers });
  } catch (e) {
    return new Response("Internal Encryption Error", { status: 500 });
  }
}

async function generateResponseForVirtualFile(request, clientId) {
  try {
    const url = new URL(request.url);
    const { mode } = request;

    // This forces a specific reload with ?boot=1 to ensure the context is "clean" and controlled for Firefox because Firefox is weird.
    const isFirefox = typeof InternalError !== "undefined";
    if (isFirefox && mode === "navigate" && !url.searchParams.has("boot")) {
      url.searchParams.set("boot", "1");
      return new Response(
        `<!DOCTYPE html><script>location.replace("${url.href}");</script>`,
        {
          headers: { "Content-Type": "text/html" },
        }
      );
    }

    const virtualPath = url.pathname.substring(virtualPathPrefix.length);
    const pathParts = virtualPath.split("/").map((p) => decodeURIComponent(p));
    const folderName = pathParts[0];

    let session = clientSessionStore.get(clientId);
    if (!session && pendingNavData && pendingNavData[folderName]) {
      session = pendingNavData[folderName];
    }

    if (session) {
      session.timestamp = Date.now();
      clientSessionStore.set(clientId, session);
    }
    session = session || {};

    let relativePath = pathParts.slice(1).join("/");

    if (!relativePath || relativePath.endsWith("/"))
      relativePath += "index.html";

    let root, registry;
    try {
      root = await getOpfsRoot();
      registry = await getRegistry();
    } catch (e) {
      return new Response("System error: OPFS inaccessible", { status: 500 });
    }

    const folderData = registry[folderName] || {};
    async function getFileHandle(dir, name, path) {
      try {
        const pathParts = path
          .split("/")
          .map((p) => {
            try {
              return decodeURIComponent(p);
            } catch (e) {
              return p;
            }
          })
          .filter((p) => p && p.trim() !== "");

        const parts = [RFS_PREFIX, name, ...pathParts];

        let curr = dir;
        for (let i = 0; i < parts.length - 1; i++) {
          curr = await curr.getDirectoryHandle(parts[i]);
        }
        return await curr.getFileHandle(parts[parts.length - 1]);
      } catch (e) {
        return null;
      }
    }

    let handle = await getFileHandle(root, folderName, relativePath);

    // Fallback to index.html
    const isHtmlRequest =
      mode === "navigate" ||
      (request.headers.get("Accept") || "").includes("text/html");

    if (!handle && isHtmlRequest) {
      const indexHandle = await getFileHandle(root, folderName, "index.html");
      if (indexHandle) {
        handle = indexHandle;
        relativePath = "index.html";
      }
    }

    if (!handle) {
      return new Response("File not found", { status: 404 });
    }

    const file = await handle.getFile();
    let totalSize = file.size;

    let contentType = file.type;
    if (!contentType || contentType === "application/octet-stream") {
      contentType = getMimeType(relativePath) || "application/octet-stream";
    }

    let compiledRules = session.compiledRules;
    if (!compiledRules && folderData.rules)
      compiledRules = compileRules(folderData.rules);

    const isEncrypted = folderData.encryptionType === "password";
    const hasRegex = compiledRules && compiledRules.length > 0;
    const needsProcessing = isEncrypted || hasRegex;

    const baseHeaders = {
      "Content-Type": contentType,
      "Cache-Control": "no-store",
      "Accept-Ranges": "bytes",
    };

    const finalHeaders = applyCustomHeaders(
      baseHeaders,
      relativePath,
      session.headers || folderData.headers
    );

    // Stream directly
    if (!needsProcessing) {
      const rangeHeader = request.headers.get("Range");

      if (rangeHeader) {
        const parts = rangeHeader.replace(/bytes=/, "").split("-");
        const start = parseInt(parts[0], 10);
        const end = parts[1] ? parseInt(parts[1], 10) : totalSize - 1;

        if (start >= totalSize || end >= totalSize) {
          return new Response(null, {
            status: 416,
            headers: { "Content-Range": `bytes */${totalSize}` },
          });
        }

        const chunkSize = end - start + 1;
        const slicedBlob = file.slice(start, end + 1);

        finalHeaders["Content-Range"] = `bytes ${start}-${end}/${totalSize}`;
        finalHeaders["Content-Length"] = chunkSize;

        return new Response(slicedBlob, { status: 206, headers: finalHeaders });
      }

      finalHeaders["Content-Length"] = totalSize;
      return new Response(file, { headers: finalHeaders });
    }

    let buffer = await file.arrayBuffer();
    if (folderData.encryptionType === "password") {
      if (!session.key)
        return new Response("Session locked. Reload from Main.", {
          status: 403,
        });
      return await handleEncryptedRequest(
        root,
        folderName,
        relativePath,
        session.key,
        request
      );
    }

    if (hasRegex) {
      buffer = applyRegexRules(
        relativePath,
        buffer,
        contentType,
        compiledRules
      );
    }

    const isHtml = contentType.includes("html");

    if (isHtml) {
      const decoder = new TextDecoder();
      let htmlContent = decoder.decode(buffer);
      const injection =
        '<script>navigator.serviceWorker.controller||navigator.serviceWorker.addEventListener("controllerchange",()=>{window.location.reload()});</script>';

      if (htmlContent.includes("</head>")) {
        htmlContent = htmlContent.replace("</head>", injection + "</head>");
      }
      buffer = new TextEncoder().encode(htmlContent).buffer;
    }

    const processedSize = buffer.byteLength;
    const rangeHeader = request.headers.get("Range");

    if (rangeHeader) {
      const parts = rangeHeader.replace(/bytes=/, "").split("-");
      let start = parseInt(parts[0], 10);
      let end = parts[1] ? parseInt(parts[1], 10) : processedSize - 1;

      if (isNaN(start)) start = 0;
      if (isNaN(end)) end = processedSize - 1;
      if (end >= processedSize) end = processedSize - 1;

      if (start >= processedSize) {
        return new Response(null, {
          status: 416,
          headers: { "Content-Range": `bytes */${processedSize}` },
        });
      }

      const chunkSize = end - start + 1;
      const slicedBuffer = buffer.slice(start, end + 1);

      finalHeaders["Content-Range"] = `bytes ${start}-${end}/${processedSize}`;
      finalHeaders["Content-Length"] = chunkSize;

      return new Response(slicedBuffer, { status: 206, headers: finalHeaders });
    }

    finalHeaders["Content-Length"] = processedSize;
    return new Response(buffer, { headers: finalHeaders });
  } catch (e) {
    console.error("SW error:", e);
    return new Response("Internal error", { status: 500 });
  }
}

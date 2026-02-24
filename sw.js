const APP_SHELL_FILES = ["./", "./index.html", "./main.min.js", "sw.min.js"]; // If you're using .php or some other configuration, make sure to change this!
const NETWORK_ALLOWLIST_PREFIXES = []; // For custom bypassing of the virtual file system (not used by default)

// Old SpiderMonkey check, because Firefox previously had weird SW header issues. ?boot=1 is used to ensure the context is "clean" and controlled because Firefox acted strangely with SWs in older versions; use `typeof InternalError !== "undefined"` to re-enable with Firefox.
let reloadOnRequest = false;

let pendingNavData = null; // for next navigation request
const clientSessionStore = new Map();
const handleCache = new Map();
const manifestCache = new Map();
const ruleCache = new Map();
const MAX_REGEX_SIZE = 10 * 1024 * 1024; // 10 MiB default

const dirHandleCache = new Map(); // Cache for directory handles
const MAX_DIR_CACHE_SIZE = 1000; // Prevent memory leaks

function addToCache(map, key, value) {
  if (map.size >= MAX_DIR_CACHE_SIZE) map.delete(map.keys().next().value); // Simple LRU
  map.set(key, value);
}

const RFS_PREFIX = "rfs";
const SYSTEM_FILE = "rfs_system.json";
const CACHE_NAME = "fc";
const FULL_APP_SHELL_URLS = APP_SHELL_FILES.map(
  (file) => new URL(file, self.location.href).href,
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
  return mimeTypes[ext] || "text/plain";
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
    let replacePart = parts.slice(1).join("->").trim();

    // Parse the operator (like | or $$)
    const operatorMatch = matchPart.match(
      /^(.*?)\s+(\$|\$\$|\|\||\|)\s+(.*)$/s,
    );
    if (!operatorMatch) continue;

    // funy JS trick
    const [, fileMatch, operator, searchPattern] = operatorMatch;
    try {
      const fileRegex = new RegExp(
        fileMatch.trim() === "*" ? ".*" : fileMatch.trim(),
      );
      let searchRegex;

      if (searchPattern === "{{SCRIPT}}") {
        searchRegex =
          /(?:<!DOCTYPE\b[^>]*>)|(?:<head\b[^>]*>)|(?:<body\b[^>]*>)|(?:<html\b[^>]*>)|(?:^)/i;
        replacePart = `$&<script>${replacePart}</script>`;
      } else {
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
      }

      if (searchRegex && fileRegex) {
        compiled.push({ fileRegex, searchRegex, replacePart });
      }
    } catch (e) {
      console.warn("Rule compilation failed for line " + line + ":", e);
      continue;
    }
  }

  if (ruleCache.size > 50) ruleCache.clear();
  ruleCache.set(rulesString, compiled);
  return compiled;
}

function applyRegexRules(filePath, fileBuffer, fileType, compiledRules) {
  if (
    !/^(text\/|application\/(javascript|json|xml|x-javascript|typescript))/.test(
      fileType,
    )
  )
    return fileBuffer;
  if (fileBuffer.byteLength > MAX_REGEX_SIZE) return fileBuffer;

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

async function getCachedFileHandle(root, folderName, relativePath) {
  const fileCacheKey = `${folderName}|${relativePath}`;

  if (handleCache.has(fileCacheKey)) return handleCache.get(fileCacheKey);

  try {
    const pathParts = relativePath
      .split("/")
      .filter((p) => p && p.trim() !== "");
    const fileName = decodeURIComponent(pathParts.pop());

    let currentDirHandle;
    let currentPathKey = folderName; // Start at the folder root
    if (dirHandleCache.has(currentPathKey)) {
      currentDirHandle = dirHandleCache.get(currentPathKey);
    } else {
      // Cold start: Get RFS root to folder root
      const rfsHandle = await root.getDirectoryHandle(RFS_PREFIX);
      currentDirHandle = await rfsHandle.getDirectoryHandle(folderName);
      addToCache(dirHandleCache, currentPathKey, currentDirHandle);
    }

    // Go through subdirectories using cache
    for (const part of pathParts) {
      const decodedPart = decodeURIComponent(part);
      currentPathKey += `/${decodedPart}`;

      if (dirHandleCache.has(currentPathKey)) {
        currentDirHandle = dirHandleCache.get(currentPathKey);
      } else {
        currentDirHandle =
          await currentDirHandle.getDirectoryHandle(decodedPart);
        addToCache(dirHandleCache, currentPathKey, currentDirHandle);
      }
    }

    const fileHandle = await currentDirHandle.getFileHandle(fileName);
    addToCache(handleCache, fileCacheKey, fileHandle);
    return fileHandle;
  } catch (e) {
    return null;
  }
}

self.addEventListener("install", async function installCache() {
  const cache = await caches.open(CACHE_NAME);
  await Promise.all(
    APP_SHELL_FILES.map(async (url) => {
      try {
        const response = await fetch(url, { cache: "reload" });
        if (response.ok) await cache.put(url, response);
      } catch (e) {
        console.warn("Failed to cache app shell file:", url);
      }
    }),
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
      } catch (e) {}
      const allClients = await self.clients.matchAll({
        includeUncontrolled: true,
      });
      for (const client of allClients) client.postMessage({ type: "SW_READY" });
    })(),
  );
});

self.addEventListener("message", (e) => {
  if (!e.data) return;
  const clientId = e.source ? e.source.id : null;

  switch (e.data.type) {
    case "SET_RULES":
      const { rules, headers, key, folderName } = e.data;
      const compiledRules = compileRules(rules);
      const compiledHeaders = parseCustomHeaders(headers);

      if (!pendingNavData) pendingNavData = {};
      pendingNavData[folderName] = {
        rules,
        compiledRules,
        headers, // Keep raw string just in case
        compiledHeaders, // Store compiled version
        key,
        timestamp: Date.now(),
      };

      if (clientId) {
        const s = clientSessionStore.get(clientId) || {};
        s.rules = rules;
        s.compiledRules = compiledRules;
        s.headers = headers;
        s.compiledHeaders = compiledHeaders; // Store here too
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
      dirHandleCache.clear();
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
        })(),
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
      const headerValue = fullHeaderString
        .substring(colonIndex + 1)
        .trim()
        .replace(/^['"]|['"]$/g, ""); // remove quotes at start and end

      try {
        const regex = new RegExp(
          "^" +
            glob
              .replace(/\./g, "\\.")
              .replace(/\*/g, ".*")
              .replace(/\?/g, ".") +
            "$",
        );
        rules.push({ regex, header: headerName, value: headerValue });
      } catch (e) {}
    });
  return rules;
}

function applyCustomHeaders(baseHeaders, filePath, headerRulesArray) {
  if (!headerRulesArray || !Array.isArray(headerRulesArray)) return baseHeaders;

  for (const rule of headerRulesArray) {
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
  } else if (url.pathname.startsWith(virtualPathPrefix)) {
    const virtualPath = url.pathname.substring(virtualPathPrefix.length);
    // If there are no slashes remaining, it's a root folder access (e.g. "MyFolder")
    // A correct path would be "MyFolder/" or "MyFolder/file.html"
    if (!virtualPath.includes("/")) {
      e.respondWith(Response.redirect(url.href + "/", 301));
      return;
    }
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
    } catch (e) {}
  }

  if (virtualReferrerPath && !url.pathname.startsWith(virtualPathPrefix)) {
    const newVirtualUrl = `${self.location.origin}${virtualPathPrefix}${virtualReferrerPath}${url.pathname}`;

    e.respondWith(
      (async () => {
        const newReq = new Request(newVirtualUrl, request);
        const response = await generateResponseForVirtualFile(newReq, clientId);

        if (response.status !== 404) return response;
        if (FULL_APP_SHELL_URLS.includes(cleanUrl)) {
          const cache = await caches.match(request, { ignoreSearch: true });
          return cache || fetch(request);
        }

        return response;
      })(),
    );
    return;
  }

  if (FULL_APP_SHELL_URLS.includes(cleanUrl)) {
    e.respondWith(
      (async () => {
        const cached = await caches.match(request, { ignoreSearch: true });
        return cached || fetch(request);
      })(),
    );
    return;
  }

  if (url.pathname.startsWith(virtualPathPrefix)) {
    e.respondWith(
      generateResponseForVirtualFile(request, clientId, e.resultingClientId),
    );
    return;
  }

  e.respondWith(
    fetch(request).catch(() => new Response(null, { status: 400 })),
  );
});

async function handleEncryptedRequest(
  opfsRoot,
  folderName,
  filePath,
  key,
  request,
  customHeaders,
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
          encData,
        );
        manifest = JSON.parse(new TextDecoder().decode(dec));
        if (manifestCache.size > 5) {
          const firstKey = manifestCache.keys().next().value;
          manifestCache.delete(firstKey);
        }

        manifestCache.set(folderName, manifest);
      } catch (e) {
        return new Response("Password Incorrect", { status: 403 });
      }
    }

    const fileMeta =
      manifest[filePath] ||
      manifest[filePath + ".html"] ||
      manifest[filePath + "/index.html"];
    if (!fileMeta)
      return new Response("File not found: " + filePath, { status: 404 });

    const totalSize = fileMeta.size;

    if (totalSize === 0) {
      return new Response(new Uint8Array(0), {
        status: 200,
        headers: {
          "Content-Type": fileMeta.type || getMimeType(filePath),
          "Content-Length": "0",
        },
      });
    }

    const rawFileHandle = await getCachedFileHandle(
      opfsRoot,
      folderName,
      fileMeta.id,
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
              rawOffset + encChunkLen,
            );
            const buf = await slicedBlob.arrayBuffer();

            if (buf.byteLength === 0) break;

            const chunkIv = buf.slice(0, 12);
            const chunkCipher = buf.slice(12);

            const plain = await crypto.subtle.decrypt(
              { name: "AES-GCM", iv: chunkIv },
              key,
              chunkCipher,
            );
            const data = new Uint8Array(plain);

            const globalChunkStart = i * CHUNK_SIZE;
            const outputStart = Math.max(start, globalChunkStart);
            const outputEnd = Math.min(end + 1, globalChunkStart + data.length);

            if (outputStart < outputEnd) {
              controller.enqueue(
                data.subarray(
                  outputStart - globalChunkStart,
                  outputEnd - globalChunkStart,
                ),
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
      ...customHeaders, // Apply custom headers (CSP, etc)
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

const TEXT_MIME_REGEX =
  /^(text\/|application\/(javascript|json|xml|x-javascript|typescript|x-sh|x-httpd-php|ld\+json|manifest\+json|svg\+xml))/i;
const TEXT_EXTENSIONS =
  /\.(txt|html|htm|js|mjs|css|json|md|xml|svg|sh|php|py|rb|c|cpp|h|ts|sql|ini|yaml|yml)$/i;

function isLikelyText(type, path) {
  return TEXT_MIME_REGEX.test(type) || TEXT_EXTENSIONS.test(path);
}

function isActuallyTextSniff(buffer) {
  const view = new Uint8Array(buffer.slice(0, 4096));
  if (view.length === 0) return true;
  else if (view.includes(0)) return false;

  // Check for BOMs (UTF-8, UTF-16LE, UTF-16BE)
  if (
    (view[0] === 0xef && view[1] === 0xbb && view[2] === 0xbf) ||
    (view[0] === 0xff && view[1] === 0xfe) ||
    (view[0] === 0xfe && view[1] === 0xff)
  ) {
    return true;
  }

  try {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    decoder.decode(view);
    return true;
  } catch (e) {
    // If UTF-8 fails, check for legacy encodings (Latin-1)
    let suspiciousBytes = 0;
    for (let i = 0; i < view.length; i++) {
      const byte = view[i];
      // Check for common binary control characters (except TAB, LF, CR, etc.)
      if (byte < 7 || (byte > 14 && byte < 32)) {
        suspiciousBytes++;
      }
    }
    // If more than 5% of the sample is "garbage" control chars, it's binary probably
    return suspiciousBytes / view.length < 0.05;
  }
}

async function generateResponseForVirtualFile(
  request,
  clientId,
  resultingClientId,
) {
  try {
    const url = new URL(request.url);
    const { mode } = request;

    const virtualPath = url.pathname.substring(virtualPathPrefix.length);
    const pathParts = virtualPath.split("/").map((p) => {
      try {
        return decodeURIComponent(p);
      } catch (e) {
        return p;
      }
    });
    const folderName = pathParts[0];

    let root = await getOpfsRoot();
    if (!registryCache) await getRegistry();
    const registry = registryCache || {};
    const folderData = registry[folderName] || {};

    // Here the boot-up logic happens (but only if the reloadOnRequest is enabled)
    if (
      reloadOnRequest &&
      mode === "navigate" &&
      !url.searchParams.has("boot")
    ) {
      url.searchParams.set("boot", "1");
      return new Response(
        `<!DOCTYPE html><script>location.replace("${url.href}")</script>`,
        { headers: { "Content-Type": "text/html" } },
      );
    }

    const effectiveClientId = resultingClientId || clientId;
    let session =
      clientSessionStore.get(effectiveClientId) ||
      (clientId ? clientSessionStore.get(clientId) : null);

    if (!session && pendingNavData && pendingNavData[folderName]) {
      session = pendingNavData[folderName];
    }
    if (session) {
      session.timestamp = Date.now();
      if (effectiveClientId) clientSessionStore.set(effectiveClientId, session);
    }
    session = session || {};

    let relativePath = pathParts.slice(1).join("/");
    if (!relativePath || relativePath.endsWith("/"))
      relativePath += "index.html";

    if (folderData.encryptionType === "password") {
      if (!session.key) return new Response("Session locked", { status: 403 });
      const compiledHeaders =
        session.compiledHeaders || parseCustomHeaders(folderData.headers);
      const headers = applyCustomHeaders(
        {
          "Content-Type": getMimeType(relativePath),
          "Cache-Control": "no-store",
          "Accept-Ranges": "bytes",
        },
        relativePath,
        compiledHeaders,
      );

      return await handleEncryptedRequest(
        root,
        folderName,
        relativePath,
        session.key,
        request,
        headers,
      );
    }

    let handle = await getCachedFileHandle(root, folderName, relativePath);

    if (!handle && !relativePath.includes(".") && !relativePath.endsWith("/")) {
      const htmlHandle = await getCachedFileHandle(
        root,
        folderName,
        relativePath + ".html",
      );
      if (htmlHandle) {
        handle = htmlHandle;
        relativePath += ".html";
      }
    }

    let status = 200;

    if (
      !handle &&
      (mode === "navigate" ||
        (request.headers.get("Accept") || "").includes("text/html"))
    ) {
      const errorHandle = await getCachedFileHandle(
        root,
        folderName,
        "404.html",
      );
      if (errorHandle) {
        handle = errorHandle;
        relativePath = "404.html";
        status = 404;
      } else if (!relativePath.endsWith("index.html")) {
        // Standard SPA fallback
        const indexHandle = await getCachedFileHandle(
          root,
          folderName,
          "index.html",
        );
        if (indexHandle) {
          handle = indexHandle;
          relativePath = "index.html";
        }
      }
    }

    if (!handle)
      return new Response(
        "File not found: " + folderName + "/" + relativePath,
        { status: 404 },
      );

    const file = await handle.getFile();
    const totalSize = file.size;
    const contentType =
      file.type || getMimeType(relativePath) || "application/octet-stream";

    const compiledHeaders =
      session.compiledHeaders || parseCustomHeaders(folderData.headers);
    const compiledRules =
      session.compiledRules || compileRules(folderData.rules);

    let finalHeaders = applyCustomHeaders(
      {
        "Content-Type": contentType,
        "Cache-Control": "no-store",
        "Accept-Ranges": "bytes",
      },
      relativePath,
      compiledHeaders,
    );

    let responseBody = file;
    let processedSize = totalSize;

    if (
      compiledRules &&
      compiledRules.length > 0 &&
      totalSize > 0 &&
      totalSize <= MAX_REGEX_SIZE
    ) {
      if (isLikelyText(contentType, relativePath)) {
        // Only read the first 4KB to check if it's actually text
        const probeBuffer = await file.slice(0, 4096).arrayBuffer();

        if (isActuallyTextSniff(probeBuffer)) {
          const fullBuffer = await file.arrayBuffer();
          const processedBuffer = applyRegexRules(
            relativePath,
            fullBuffer,
            contentType,
            compiledRules,
          );

          if (processedBuffer !== fullBuffer) {
            responseBody = processedBuffer; // Serve manipulated version
            processedSize = processedBuffer.byteLength;
          } else {
            // Rules existed but didn't match.
            responseBody = fullBuffer;
          }
        }
      }
    }

    const rangeHeader = request.headers.get("Range");
    if (rangeHeader && status === 200) {
      const parts = rangeHeader.replace(/bytes=/, "").split("-");
      let start = parseInt(parts[0], 10) || 0;
      let end = parts[1] ? parseInt(parts[1], 10) : processedSize - 1;

      if (start >= processedSize) {
        return new Response(null, {
          status: 416,
          headers: { "Content-Range": `bytes */${processedSize}` },
        });
      }

      end = Math.min(end, processedSize - 1);
      const chunkLength = end - start + 1;

      finalHeaders["Content-Range"] = `bytes ${start}-${end}/${processedSize}`;
      finalHeaders["Content-Length"] = chunkLength.toString();

      const rangeSlice = responseBody.slice(start, end + 1);
      return new Response(rangeSlice, { status: 206, headers: finalHeaders });
    }

    finalHeaders["Content-Length"] = processedSize.toString();
    return new Response(responseBody, { status, headers: finalHeaders });
  } catch (e) {
    console.error("SW fetch error:", e);
    return new Response("Internal server error", { status: 500 });
  }
}

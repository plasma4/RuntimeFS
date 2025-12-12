(function () {
  const CHUNK_SIZE = 4 * 1024 * 1024; // 4MB
  const ENC = new TextEncoder();
  const DEC = new TextDecoder();
  const TEMP_BLOB_DIR = ".rfs_temp_blobs"; // Hidden temp dir for IDB restoration

  async function deriveKey(password, salt) {
    const km = await crypto.subtle.importKey(
      "raw",
      ENC.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
      km,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  function isAllowed(category, path, config) {
    if (
      config.exclude?.[category]?.some(
        (t) => path === t || path.startsWith(t + "/")
      )
    )
      return false;
    if (config.include?.[category]?.length > 0) {
      return config.include[category].some(
        (t) => path === t || path.startsWith(t + "/")
      );
    }
    return true;
  }

  async function prepForCBOR(item, externalBlobs) {
    if (item instanceof Blob) {
      const uuid = crypto.randomUUID();
      externalBlobs.push({ uuid, blob: item });
      return { __le_blob_ref: uuid, type: item.type, size: item.size };
    }
    if (item instanceof ArrayBuffer) return new Uint8Array(item.slice(0));
    if (ArrayBuffer.isView(item))
      return new Uint8Array(
        item.buffer.slice(item.byteOffset, item.byteOffset + item.byteLength)
      );
    if (Array.isArray(item)) {
      return Promise.all(item.map((i) => prepForCBOR(i, externalBlobs)));
    }
    if (item && typeof item === "object") {
      const n = {};
      for (const k in item) {
        n[k] = await prepForCBOR(item[k], externalBlobs);
      }
      return n;
    }
    return item;
  }

  async function restoreFromCBOR(item, tempBlobDir) {
    if (!item || typeof item !== "object") return item;
    if (item.__le_blob_ref) {
      try {
        const fh = await tempBlobDir.getFileHandle(item.__le_blob_ref);
        const file = await fh.getFile();
        // Use slice to set the correct MIME type without wrapping the Blob in another Blob
        return file.slice(0, file.size, item.type);
      } catch (e) {
        console.warn("Missing blob ref:", item.__le_blob_ref);
        return null;
      }
    }
    if (item.__le_blob) {
      return new Blob([item.data], { type: item.type });
    }
    if (Array.isArray(item)) {
      return Promise.all(item.map((i) => restoreFromCBOR(i, tempBlobDir)));
    }
    if (item.constructor === Object) {
      const n = {};
      for (const k in item) {
        n[k] = await restoreFromCBOR(item[k], tempBlobDir);
      }
      return n;
    }
    return item;
  }

  function createTarHeader(filename, size, isDir = false) {
    const buffer = new Uint8Array(512);
    let name = filename;
    let prefix = "";
    if (name.length > 100) {
      let splitIndex = name.lastIndexOf("/", 154);
      if (splitIndex === -1 || splitIndex < name.length - 100)
        splitIndex = Math.max(0, name.length - 100);
      prefix = name.slice(0, splitIndex);
      name = name.slice(splitIndex + (prefix ? 1 : 0));
    }
    const writeStr = (str, offset, len) => {
      const b = ENC.encode(str);
      for (let i = 0; i < Math.min(len, b.length); i++)
        buffer[offset + i] = b[i];
    };
    const writeOctal = (num, offset, len) =>
      writeStr(num.toString(8).padStart(len - 1, "0"), offset, len - 1);
    writeStr(name, 0, 100);
    writeOctal(0o664, 100, 8);
    writeOctal(0, 108, 8);
    writeOctal(0, 116, 8);
    writeOctal(size, 124, 12);
    writeOctal(Math.floor(Date.now() / 1000), 136, 12);
    writeStr("        ", 148, 8);
    buffer[156] = isDir ? 53 : 48;
    writeStr("ustar", 257, 6);
    writeStr("00", 263, 2);
    if (prefix) writeStr(prefix, 345, 155);
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += buffer[i];
    writeOctal(sum, 148, 7);
    return buffer;
  }

  class TarWriter {
    constructor(writableStream) {
      this.writer = writableStream.getWriter();
      this.pos = 0;
      this.bytesWritten = 0;
    }
    async writeEntry(path, data) {
      let bytes = typeof data === "string" ? ENC.encode(data) : data;
      await this.write(createTarHeader(path, bytes.length));
      await this.write(bytes);
      await this.pad();
    }
    async writeStream(path, size, readableStream) {
      await this.write(createTarHeader(path, size));
      await readableStream.pipeTo(
        new WritableStream({
          write: async (chunk) => {
            await this.write(chunk);
          },
        })
      );
      await this.pad();
    }
    async write(chunk) {
      await this.writer.write(chunk);
      this.pos += chunk.byteLength;
      this.bytesWritten += chunk.byteLength;
    }
    async pad() {
      const padding = (512 - (this.pos % 512)) % 512;
      if (padding > 0) await this.write(new Uint8Array(padding));
    }
    async close() {
      await this.write(new Uint8Array(1024));
      await this.writer.close();
    }
  }

  class EncryptionTransformer {
    constructor(password, salt) {
      this.salt = salt;
      this.keyPromise = deriveKey(password, salt);
      this.pending = new Uint8Array(0);
    }
    async start(controller) {
      controller.enqueue(ENC.encode("LE_ENC"));
      controller.enqueue(this.salt);
      // Empty block for alignment/reserved
      await this.encryptAndPush(
        new Uint8Array(0),
        controller,
        await this.keyPromise
      );
    }
    async transform(chunk, controller) {
      const key = await this.keyPromise;
      const newPending = new Uint8Array(this.pending.length + chunk.length);
      newPending.set(this.pending);
      newPending.set(chunk, this.pending.length);
      this.pending = newPending;

      while (this.pending.length >= CHUNK_SIZE) {
        const slice = this.pending.slice(0, CHUNK_SIZE);
        this.pending = this.pending.slice(CHUNK_SIZE);
        await this.encryptAndPush(slice, controller, key);
      }
    }
    async flush(controller) {
      if (this.pending.length > 0) {
        await this.encryptAndPush(
          this.pending,
          controller,
          await this.keyPromise
        );
      }
    }
    async encryptAndPush(data, controller, key) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        data
      );
      const lenParams = new DataView(new ArrayBuffer(4));
      lenParams.setUint32(0, ciphertext.byteLength, true);
      controller.enqueue(iv);
      controller.enqueue(new Uint8Array(lenParams.buffer));
      controller.enqueue(new Uint8Array(ciphertext));
    }
  }

  // Improved DecryptionSource that doesn't merge arrays aggressively
  class DecryptionSource {
    constructor(readableStream, password) {
      this.stream = readableStream;
      this.password = password;
      this.buffer = new Uint8Array(0);
    }
    readable() {
      const self = this;
      let reader;
      let buffer = new Uint8Array(0);

      async function readMore() {
        const { value, done } = await reader.read();
        if (done) return false;
        if (buffer.length === 0) {
          buffer = value;
        } else {
          const t = new Uint8Array(buffer.length + value.length);
          t.set(buffer);
          t.set(value, buffer.length);
          buffer = t;
        }
        return true;
      }

      async function ensure(n) {
        while (buffer.length < n) {
          if (!(await readMore())) return false;
        }
        return true;
      }

      function consume(n) {
        const v = buffer.slice(0, n);
        buffer = buffer.slice(n);
        return v;
      }

      return new ReadableStream({
        async start(controller) {
          reader = self.stream.getReader();
          try {
            if (!(await ensure(22))) throw new Error("File too small");
            const sig = new TextDecoder().decode(consume(6));
            if (sig !== "LE_ENC") throw new Error("Not an encrypted archive");
            const salt = consume(16);
            const key = await deriveKey(self.password, salt);

            // Consume initial empty block
            if (!(await ensure(16))) throw new Error("Corrupt header");
            const hIv = consume(12);
            const hLen = new DataView(consume(4).buffer).getUint32(0, true);
            if (!(await ensure(hLen))) throw new Error("Corrupt header");
            consume(hLen); // discard empty block ciphertext

            while (true) {
              if (buffer.length < 16) {
                if (!(await readMore())) {
                  if (buffer.length === 0) break; // Clean EOF
                  // If bytes remain but less than 16, it's corrupt or truncated
                  if (buffer.length < 16) break;
                }
              }
              // Need at least 16 bytes for IV+Len
              if (buffer.length < 16) await ensure(16);
              if (buffer.length < 16) break;

              const iv = consume(12);
              const lenVal = new DataView(consume(4).buffer).getUint32(0, true);

              // Ensure we have the full ciphertext chunk
              while (buffer.length < lenVal) {
                if (!(await readMore()))
                  throw new Error("Unexpected EOF in ciphertext");
              }

              const cipher = consume(lenVal);
              const plain = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv },
                key,
                cipher
              );
              controller.enqueue(new Uint8Array(plain));
            }
            controller.close();
          } catch (e) {
            controller.error(e);
          } finally {
            reader.releaseLock();
          }
        },
      });
    }
  }

  async function exportData(config = {}) {
    const CBOR = window.CBOR;
    const opts = {
      fileName: "archive",
      opfs: true,
      localStorage: true,
      session: true,
      cookies: true,
      idb: true,
      cache: true,
      customItems: [],
      include: {},
      exclude: {},
      dbFilter: () => true,
      ...config,
    };
    const logger = opts.logger || console.log;

    let outputStream, downloadUrl;
    if (window.showSaveFilePicker && opts.download !== false) {
      try {
        const name = opts.password
          ? `${opts.fileName}.enc`
          : `${opts.fileName}.tar.gz`;
        const handle = await window.showSaveFilePicker({ suggestedName: name });
        outputStream = await handle.createWritable();
      } catch (e) {
        if (e.name === "AbortError") return logger("Export cancelled.");
        console.warn("FS Picker failed, fallback to blob");
      }
    }

    if (!outputStream) {
      const chunks = [];
      outputStream = new WritableStream({
        write(c) {
          chunks.push(c);
        },
        close() {
          downloadUrl = URL.createObjectURL(
            new Blob(chunks, { type: "application/octet-stream" })
          );
        },
      });
    }

    let targetStream = outputStream;
    if (opts.password) {
      logger("Encrypting...");
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const encStream = new TransformStream(
        new EncryptionTransformer(opts.password, salt)
      );
      encStream.readable.pipeTo(targetStream);
      targetStream = encStream.writable;
    }

    const gzip = new CompressionStream("gzip");
    gzip.readable.pipeTo(targetStream);
    const tar = new TarWriter(gzip.writable);

    // Initial progress reporter
    const reportProgress = () => {
      const mb = (tar.bytesWritten / 1024 / 1024).toFixed(2);
      logger(`Exporting... ${mb} MB written`);
    };
    const progressInterval = setInterval(reportProgress, 500);

    try {
      for (const item of opts.customItems) {
        logger(`Archiving custom: ${item.path}`);
        const path = `data/custom/${item.path}`;
        if (item.data instanceof Blob)
          await tar.writeStream(path, item.data.size, item.data.stream());
        else
          await tar.writeEntry(
            path,
            typeof item.data === "string"
              ? item.data
              : JSON.stringify(item.data)
          );
      }

      if (opts.localStorage) {
        const d = {};
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i);
          if (isAllowed("localStorage", k, opts))
            d[k] = localStorage.getItem(k);
        }
        await tar.writeEntry("data/ls.json", JSON.stringify(d));
      }
      if (opts.session) {
        const d = {};
        for (let i = 0; i < sessionStorage.length; i++) {
          const k = sessionStorage.key(i);
          if (isAllowed("session", k, opts)) d[k] = sessionStorage.getItem(k);
        }
        await tar.writeEntry("data/ss.json", JSON.stringify(d));
      }
      if (opts.cookies) {
        const c = document.cookie.split(";").reduce((acc, v) => {
          const [key, val] = v.split("=").map((s) => s.trim());
          if (key) acc[key] = val;
          return acc;
        }, {});
        await tar.writeEntry("data/cookies.json", JSON.stringify(c));
      }

      if (opts.idb && window.indexedDB && CBOR) {
        const dbs = await window.indexedDB.databases();

        for (const { name, version } of dbs) {
          if (!isAllowed("idb", name, opts) || !opts.dbFilter(name)) continue;
          logger(`Scanning IDB: ${name}`);

          const db = await new Promise((res, rej) => {
            const r = indexedDB.open(name);
            r.onsuccess = () => res(r.result);
            r.onerror = () => rej(r.error);
            r.onblocked = () => rej(new Error("Blocked"));
          });

          const storeNames = Array.from(db.objectStoreNames);
          if (storeNames.length > 0) {
            // Write Schema
            const stores = [];
            const tx = db.transaction(storeNames, "readonly");
            for (const sName of storeNames) {
              const s = tx.objectStore(sName);
              stores.push({
                name: sName,
                keyPath: s.keyPath,
                autoIncrement: s.autoIncrement,
                indexes: Array.from(s.indexNames).map((i) => {
                  const idx = s.index(i);
                  return {
                    name: idx.name,
                    keyPath: idx.keyPath,
                    unique: idx.unique,
                    multiEntry: idx.multiEntry,
                  };
                }),
              });
            }
            await tar.writeEntry(
              `data/idb/${name}/schema.cbor`,
              CBOR.encode({ name, version, stores })
            );

            for (const sName of storeNames) {
              logger(`Archiving IDB Store: ${name}/${sName}`);
              let lastKey = null;
              let chunkId = 0;
              let hasMore = true;

              while (hasMore) {
                await new Promise((r) => setTimeout(r, 0)); // yield
                const batch = await new Promise((res, rej) => {
                  const t = db.transaction(sName, "readonly");
                  const s = t.objectStore(sName);
                  const range =
                    lastKey !== null
                      ? IDBKeyRange.lowerBound(lastKey, true)
                      : null;
                  const req = s.openCursor(range);
                  const items = [];
                  req.onsuccess = (e) => {
                    const c = e.target.result;
                    if (c) {
                      items.push({ k: c.key, v: c.value });
                      if (items.length < 50) c.continue();
                      else res(items);
                    } else res(items);
                  };
                  req.onerror = () => rej(t.error);
                });

                if (batch.length > 0) {
                  lastKey = batch[batch.length - 1].k;
                  const encBatch = [];
                  const blobsInBatch = [];

                  for (const item of batch) {
                    const val = await prepForCBOR(item.v, blobsInBatch);
                    encBatch.push({ k: item.k, v: val });
                  }

                  // Write discovered blobs immediately
                  for (const b of blobsInBatch) {
                    await tar.writeStream(
                      `data/blobs/${b.uuid}`,
                      b.blob.size,
                      b.blob.stream()
                    );
                  }

                  // Write CBOR chunk
                  await tar.writeEntry(
                    `data/idb/${name}/${sName}/${chunkId++}.cbor`,
                    CBOR.encode(encBatch)
                  );
                } else {
                  hasMore = false;
                }
              }
            }
          }
          db.close();
        }
      }

      if (opts.cache && window.caches && CBOR) {
        for (const cacheName of await caches.keys()) {
          if (!isAllowed("cache", cacheName, opts)) continue;
          logger(`Archiving Cache: ${cacheName}`);
          const cache = await caches.open(cacheName);
          for (const req of await cache.keys()) {
            const res = await cache.match(req);
            if (!res) continue;
            const blob = await res.blob();
            const safeHash = btoa(req.url).slice(0, 50).replace(/\//g, "_");

            await tar.writeEntry(
              `data/cache/${encodeURIComponent(cacheName)}/${safeHash}.cbor`,
              CBOR.encode({
                meta: {
                  url: req.url,
                  status: res.status,
                  headers: Object.fromEntries(res.headers),
                  type: blob.type,
                },
                data: new Uint8Array(await blob.arrayBuffer()),
              })
            );
          }
        }
      }

      if (opts.opfs && navigator.storage) {
        const root = await navigator.storage.getDirectory();
        async function walk(dir, p) {
          for await (const entry of dir.values()) {
            const fp = p ? `${p}/${entry.name}` : entry.name;
            if (!isAllowed("opfs", fp, opts)) continue;
            if (entry.kind === "file") {
              const f = await entry.getFile();
              await tar.writeStream(`opfs/${fp}`, f.size, f.stream());
            } else await walk(entry, fp);
          }
        }
        await walk(root, "");
      }

      await tar.close();
      if (downloadUrl) {
        const a = document.createElement("a");
        a.href = downloadUrl;
        a.download = opts.password
          ? `${opts.fileName}.enc`
          : `${opts.fileName}.tar.gz`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
      }
      logger("Export complete!");
    } catch (e) {
      logger("Export error: " + e.message);
      console.error(e);
      try {
        await targetStream.abort(e);
      } catch (z) {}
    } finally {
      clearInterval(progressInterval);
    }
  }

  async function importData(arg1, arg2 = {}) {
    const CBOR = window.CBOR;

    let config = arg2;
    let sourceInput = arg1;

    // Check if first arg is the config object (Object style)
    if (
      arg1 &&
      typeof arg1 === "object" &&
      !arg1.stream &&
      !arg1.arrayBuffer &&
      !arg1.slice &&
      (arg1.source || arg1.include || arg1.exclude)
    ) {
      config = arg1;
      sourceInput = config.source;
    }

    const opts = { ...config };
    const logger = opts.logger || console.log;

    try {
      let rawStream;
      if (typeof sourceInput === "string") {
        // Assume URL (HTTPS link)
        const response = await fetch(sourceInput);
        if (!response.ok) {
          throw new Error(
            `Failed to fetch source: ${response.status} ${response.statusText}`
          );
        }
        if (!response.body) throw new Error("Source URL returned no data");
        rawStream = response.body;
      } else if (sourceInput && typeof sourceInput.stream === "function") {
        // Blob/file
        rawStream = sourceInput.stream();
      } else {
        throw new Error("Invalid source. Must be a Blob, File, or URL string.");
      }

      const rawReader = rawStream.getReader();
      let probeBuffer = new Uint8Array(0);

      // Read at least 8 bytes for signature check
      while (probeBuffer.length < 8) {
        const { value, done } = await rawReader.read();
        if (done) break;
        const temp = new Uint8Array(probeBuffer.length + value.length);
        temp.set(probeBuffer);
        temp.set(value, probeBuffer.length);
        probeBuffer = temp;
      }

      // Now reconstruct the stream with the probed bytes prepended
      const streamWithProbe = new ReadableStream({
        start(controller) {
          if (probeBuffer.length > 0) controller.enqueue(probeBuffer);
        },
        async pull(controller) {
          const { value, done } = await rawReader.read();
          if (done) controller.close();
          else controller.enqueue(value);
        },
        cancel(reason) {
          rawReader.cancel(reason);
        },
      });

      // Determine the format, setup pipeline
      const probeHeader = probeBuffer.slice(0, 8);
      const sig = DEC.decode(probeHeader.slice(0, 6));
      let inputStream;

      if (sig === "LE_ENC") {
        // Encrypted
        let password = opts.password;
        if (!password) {
          password = prompt("Enter the password:");
        }
        if (!password)
          throw new AbortError("Password required to decrypt data.");

        inputStream = new DecryptionSource(streamWithProbe, password)
          .readable()
          .pipeThrough(new DecompressionStream("gzip"));
      } else if (probeHeader[0] === 0x1f && probeHeader[1] === 0x8b) {
        // Standard GZIP
        inputStream = streamWithProbe.pipeThrough(
          new DecompressionStream("gzip")
        );
      } else {
        // Plain TAR
        inputStream = streamWithProbe;
      }

      const reader = inputStream.getReader();
      const rootOpfs = await navigator.storage.getDirectory();
      const dbCache = {};

      // Temp directory for restoring blobs (IDB references)
      let tempBlobDir;
      try {
        tempBlobDir = await rootOpfs.getDirectoryHandle(TEMP_BLOB_DIR, {
          create: true,
        });
      } catch (e) {}

      let buffer = new Uint8Array(0);
      let done = false;
      let totalRead = 0;
      let lastLog = 0;

      async function readMore() {
        const { value, done: d } = await reader.read();
        if (d) done = true;
        else {
          totalRead += value.length;
          if (buffer.length === 0) buffer = value;
          else {
            const t = new Uint8Array(buffer.length + value.length);
            t.set(buffer);
            t.set(value, buffer.length);
            buffer = t;
          }
        }
      }

      async function ensure(n) {
        while (buffer.length < n && !done) await readMore();
        return buffer.length >= n;
      }

      function consume(n) {
        const v = buffer.slice(0, n);
        buffer = buffer.slice(n);
        return v;
      }

      async function streamToWriter(writer, size) {
        let remaining = size;
        if (buffer.length > 0) {
          const toWrite = Math.min(buffer.length, remaining);
          await writer.write(buffer.slice(0, toWrite));
          buffer = buffer.slice(toWrite);
          remaining -= toWrite;
        }
        while (remaining > 0) {
          const { value, done: d } = await reader.read();
          if (d) {
            done = true;
            break;
          }
          totalRead += value.length;
          if (value.length <= remaining) {
            await writer.write(value);
            remaining -= value.length;
          } else {
            await writer.write(value.slice(0, remaining));
            buffer = value.slice(remaining);
            remaining = 0;
          }
        }
        await writer.close();
      }

      async function readToMemory(size) {
        if (!(await ensure(size))) throw new Error("Unexpected EOF");
        return consume(size);
      }

      async function skip(size) {
        let remaining = size;
        while (remaining > 0) {
          if (buffer.length > 0) {
            const take = Math.min(buffer.length, remaining);
            buffer = buffer.slice(take);
            remaining -= take;
          } else {
            const { value, done: d } = await reader.read();
            if (d) {
              done = true;
              break;
            }
            totalRead += value.length;
            if (value.length <= remaining) remaining -= value.length;
            else {
              buffer = value.slice(remaining);
              remaining = 0;
            }
          }
        }
      }

      while (true) {
        const now = Date.now();
        if (now - lastLog > 500) {
          logger(
            `Importing... ${(totalRead / 1024 / 1024).toFixed(2)} MB read`
          );
          lastLog = now;
          await new Promise((r) => setTimeout(r, 0));
        }

        if (!(await ensure(512))) break;
        const header = consume(512);
        if (header.every((b) => b === 0)) break; // End of TAR

        // Parse header
        let name = DEC.decode(header.slice(0, 100)).replace(/\0/g, "").trim();
        const prefix = DEC.decode(header.slice(345, 500))
          .replace(/\0/g, "")
          .trim();
        if (prefix) name = `${prefix}/${name}`;

        const sizeStr = DEC.decode(header.slice(124, 136))
          .replace(/\0/g, "")
          .trim();
        const size = parseInt(sizeStr, 8);
        if (isNaN(size)) {
          logger("Warning: Invalid TAR header found. Stopping.");
          break;
        }

        const padding = (512 - (size % 512)) % 512;

        if (name.startsWith("data/")) {
          // Metadata & Blobs
          if (name.startsWith("data/blobs/")) {
            // Restore Blob to Temp OPFS
            const uuid = name.split("/").pop();
            if (tempBlobDir) {
              const fh = await tempBlobDir.getFileHandle(uuid, {
                create: true,
              });
              const w = await fh.createWritable();
              await streamToWriter(w, size);
            } else {
              await skip(size);
            }
          } else {
            // JSON/CBOR Metadata
            if (size === 0) {
              await skip(padding);
              continue;
            }
            // Potential bottleneck with memory here
            const d = await readToMemory(size);

            if (name === "data/ls.json") {
              Object.assign(localStorage, JSON.parse(DEC.decode(d)));
            } else if (name === "data/ss.json") {
              const s = JSON.parse(DEC.decode(d));
              for (const k in s) sessionStorage.setItem(k, s[k]);
            } else if (name === "data/cookies.json") {
              const c = JSON.parse(DEC.decode(d));
              for (const k in c)
                document.cookie = `${k}=${c[k]}; path=/; max-age=31536000`;
            } else if (name.startsWith("data/custom/") && opts.onCustomItem) {
              await opts.onCustomItem(name.replace("data/custom/", ""), d);
            } else if (
              name.startsWith("data/idb/") &&
              CBOR &&
              opts.idb !== false
            ) {
              // IndexedDB Restoration
              const parts = name.split("/");
              const dbName = parts[2];

              if (name.endsWith("schema.cbor")) {
                const schema = CBOR.decode(d);
                if (dbCache[dbName]) dbCache[dbName].close();

                await new Promise((r) => {
                  const q = indexedDB.deleteDatabase(schema.name);
                  q.onsuccess = r;
                  q.onerror = r;
                  q.onblocked = r;
                });

                await new Promise((res, rej) => {
                  const req = indexedDB.open(schema.name, schema.version);
                  req.onupgradeneeded = (e) => {
                    const db = e.target.result;
                    schema.stores.forEach((s) => {
                      if (!db.objectStoreNames.contains(s.name)) {
                        const st = db.createObjectStore(s.name, {
                          keyPath: s.keyPath,
                          autoIncrement: s.autoIncrement,
                        });
                        s.indexes.forEach((i) =>
                          st.createIndex(i.name, i.keyPath, {
                            unique: i.unique,
                            multiEntry: i.multiEntry,
                          })
                        );
                      }
                    });
                  };
                  req.onsuccess = (e) => {
                    e.target.result.close();
                    res();
                  };
                  req.onerror = rej;
                });
              } else {
                const storeName = parts[3];
                const records = await restoreFromCBOR(
                  CBOR.decode(d),
                  tempBlobDir
                );

                if (!dbCache[dbName]) {
                  dbCache[dbName] = await new Promise((res, rej) => {
                    const r = indexedDB.open(dbName);
                    r.onsuccess = () => res(r.result);
                    r.onerror = rej;
                  });
                }
                const tx = dbCache[dbName].transaction(storeName, "readwrite");
                const st = tx.objectStore(storeName);
                records.forEach((r) =>
                  st.put(r.v, st.keyPath ? undefined : r.k)
                );
              }
            }
          }
        } else {
          // File System (OPFS)
          if (opts.opfs !== false) {
            const cleanName = name.startsWith("opfs/")
              ? name.replace("opfs/", "")
              : name;

            const parts = cleanName.split("/").filter((p) => p.length > 0);
            if (parts.length > 0) {
              const fname = parts.pop();
              let dir = rootOpfs;
              for (const p of parts) {
                dir = await dir.getDirectoryHandle(p, { create: true });
              }

              const fh = await dir.getFileHandle(fname, { create: true });
              const w = await fh.createWritable();
              if (size > 0) await streamToWriter(w, size);
              else await w.close();
            } else {
              if (size > 0) await skip(size);
            }
          } else {
            if (size > 0) await skip(size);
          }
        }
        await skip(padding);
      }

      // Cleanup
      Object.values(dbCache).forEach((db) => db.close());
      if (tempBlobDir) {
        try {
          await rootOpfs.removeEntry(TEMP_BLOB_DIR, { recursive: true });
        } catch (e) {}
      }

      logger("Import complete!");
      if (opts.onsuccess) opts.onsuccess();
    } catch (e) {
      logger("Error: " + e.message);
      if (opts.onerror) opts.onerror(e);
      else throw e;
    }
  }

  window.LittleExport = { importData, exportData, deriveKey };
})();

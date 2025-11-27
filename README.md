# RuntimeFS
![RuntimeFS explanation](RuntimeFS.png)
View the [working demo](https://runtimefs.netlify.app/)!

RuntimeFS is a no-nonsense `OPFS` and `ServiceWorker` file-system, served in your browser. It allows you to open HTML projects, use some encryption techniques, and comes with **full offline** and **complete .tar.gz or encrypted data export** functionality that no other tool has!

Imagine an offline localhost, in your browser with no server-based storage of files. It saves all files and data locally, and can easily be integrated within an existing website too (the code is under the MIT License, and only around 50KB).

After initial page load, RuntimeFS no longer needs internet connection to function.
RuntimeFS has been tested in Chromium, Safari, Firefox (although File System API features are Chromium-exclusive).

If you are hosting this, you can minify the JavaScript files first with a tool like https://jscompress.com/.

## Browser Support
(Safari only works in version 26.0 and above.)
(Firefox has a very specific issue involving initially loading JS scripts in `generateResponseForVirtualFile`, so an automatic reload is performed that injects `?boot=1` to the end of the URL.)
| Feature | 🟢 Chromium | 🟡 Firefox | 🟡 Safari |
| :--- | :--- | :--- | :--- |
| **Folder Upload** | ✅ Yes | ⚠️ `<input>` fallback, no sync | ⚠️ `<input>` fallback, no sync |
| **Encryption (folder-based)** | ✅ Yes | ❌ No | ❌ No |
| **Export (including encryption)** | ✅ Stream to Disk | ⚠️ RAM Only (crashes if too big) | ⚠️ RAM Only (crashes if too big) |

## Notes
Do note that many projects might not work; projects that use **synchronous** AJAX requests (commonly done with JQuery's `$.ajax({type: "GET", url: "...", async: false })`) will not work due to fundamental ServiceWorker limitations. (This type of request is also being phased out from browsers gradually; I've tried getting this working with `Atomics` and web workers but it sadly isn't possible to fix at all.)

Additionally, file names are case-sensitive. Using the tool in Incognito will probably fail due to restrictions on memory or ServiceWorker.

A single-file plugin exists for customizing cache in the `plugin` (or requesting an update), allowing for you to fully customize RuntimeFS from any site hosting it (although **it will clear the cache on hard reload**).

Not all applications will work! Out of the many sites I tested, there were the main reasons why they broke, even with custom headers:
- The application isn't compiled yet on a GitHub download (think Vite).
- The application requests something externally (this might not always break, but sometimes sites are strict!). ServiceWorkers cannot intercept these anyway.
- Somewhere in the application, sync AJAX is used.
- Literal voodoo magic (one example is [Webleste](https://celeste.r58playz.dev/) breaking in the newest version, but an [older version](https://github.com/plasma4/RuntimeFS/tree/e8ed253071cbc53d446b622aa6426e4f5c525e6b) that uses an IndexedDB architecture mysteriously works, greatly appreciated if anyone can figure out why).

> [!WARNING]
> Folders are **not sandboxed**! Because RuntimeFS serves files from the same origin, uploaded scripts have unrestricted access to local data (including `localStorage`, `IndexedDB`, and `OPFS`).
>
> In theory, a malicious site hosted inside RuntimeFS could exfiltrate your data. Keep in mind you are basically using a localhost **but without subdomain/site isolation**. If this is a concern, use Content-Security-Policy (CSP) headers to stop external requests.

### TODO
- Console log and JS execution panel (for some cases where Inspect is unavailable)
- More complete documentation
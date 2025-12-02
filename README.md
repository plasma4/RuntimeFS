# RuntimeFS
![RuntimeFS explanation](RuntimeFS.png)
View the [working demo](https://runtimefs.netlify.app/)!

RuntimeFS is a no-nonsense `OPFS` and `ServiceWorker` file-system, served in your browser. It allows you to open HTML projects, use some encryption techniques, and comes with **full offline** and **complete .tar.gz or encrypted data export** functionality that no other tool has!

Imagine an offline localhost, in your browser with no server-based storage of files. It saves all files and data locally, and can easily be integrated within an existing website too (the code is MIT Licensed, and only around 100KB).

After initial page load, RuntimeFS no longer needs internet connection to function.
RuntimeFS has been tested in Chromium, Firefox, and Safari (although File System API features are Chromium-exclusive).

If you are hosting this, you can minify the JavaScript files first with a tool like https://jscompress.com/.

## Browser Support
(Safari has to be version 26.0 or above due to [`createWritable`](https://caniuse.com/mdn-api_filesystemfilehandle_createwritable), although I'm unable to verify if anything else is broken on my device.)
(Firefox has a very specific issue involving initially loading JS scripts in `generateResponseForVirtualFile`, so an automatic reload is performed that injects `?boot=1` to the end of the URL.)
| Feature | 🟢 Chromium | 🟡 Firefox | 🟡 Safari |
| :--- | :--- | :--- | :--- |
| **Folder Upload** | ✅ Yes | ⚠️ `<input>` fallback, no sync | ⚠️ `<input>` fallback, no sync |
| **Encryption (folder-based)** | ✅ Yes | ❌ No | ❌ No |
| **Export (including encryption)** | ✅ Mostly streamed to disk | ⚠️ RAM only (crashes if too big) | ⚠️ RAM only (crashes if too big) |

## Notes
There are also additional (private) variations of RuntimeFS for site hosters and developers, so do reach out to me on Discord (`@1_e0`) if you need a better implementation, encounter issues, or need clarification!

Not all applications will work! Out of the many sites I tested, there were the main reasons why they broke, even with custom headers:
- The application requests something externally (this might not always break, but sometimes sites are strict!). ServiceWorkers cannot intercept these anyway.
- Somewhere in the application, sync AJAX is used. (This type of request is also being phased out from browsers gradually; I've tried getting this working with `Atomics` and web workers but it sadly isn't fixable.)
- The application isn't compiled yet, such as on a Vite GitHub download.
- The application requests URLs from root (`/`). The current version has some fixes for this but it's not guaranteed to work for everything (or, custom `<base>` elements might actually interfere). This might be fixable with `<base href="/n/FolderName">`.
- Literal voodoo magic (one example is [Webleste](https://celeste.r58playz.dev/) breaking in the newest version, but an [older version](https://github.com/plasma4/RuntimeFS/tree/e8ed253071cbc53d446b622aa6426e4f5c525e6b) that uses an IndexedDB architecture mysteriously works (or at least gets further?), greatly appreciated if anyone can figure out why).
- RuntimeFS's regex and header settings are in localStorage (separate from the RuntimeFS export option) currently.

> [!WARNING]
> Folders are **not sandboxed**! Because RuntimeFS serves files from the same origin, uploaded scripts have unrestricted access to local data (including `localStorage`, `IndexedDB`, and `OPFS`).
>
> In theory, a malicious site hosted inside RuntimeFS could exfiltrate your data. Keep in mind you are basically using a localhost **but without subdomain/site isolation**. If this is a concern, use Content-Security-Policy (CSP) headers to stop external requests.

Also note:
- File names are case-sensitive.
- Using the tool in Incognito will probably fail due to restrictions on memory or ServiceWorkers (browser dependent).
- The most likely reason that data export fails when transferring between sites is because those websites use URL properties as part of the key (either from `document.URL` or `location`). You might be able to force a site to use a hardcoded URL for storage with clever regex or code changes.
- Using regex requires any matched files to be fully loaded into memory, reducing performance. Be careful!
- Exporting any single files with very large sizes not from OPFS (such as from IndexedDB, or cache storage) might result in crashes.
- You might encounter freezing of all RuntimeFS-related tabs if any tab is stuck or waiting for something (such as IndexedDB).

A single-file plugin exists for customizing cache in the `plugin` (or requesting an update), allowing for you to fully customize RuntimeFS from any site hosting it (although **it will clear the cache on hard reload**).

### TODO
- Devtools panel (for some cases where Inspect is unavailable, using something like Eruda)
- More complete documentation
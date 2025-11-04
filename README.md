# RuntimeFS
View the [working demo](https://runtimefs.netlify.app)!

RuntimeFS is a no-nonsense `IndexedDB` and `ServiceWorker` file-system, served in your browser. It allows you to open HTML projects, use some encryption techniques, and comes with **full offline** and **data export** functionality!

Imagine a localhost, in your browser, with no traces of network activity of files hosted and no server-based storage of files. It saves all files and data locally, and can easily be integrated within an existing website too (the code is under the MIT License).

After initial page load, RuntimeFS no longer needs internet connection to function.
RuntimeFS has been tested in Chromium and Firefox (although most features will never work for Firefox, as they use the File System API). Using the tool in Incognito might fail due to memory limitations with a `QuotaExceededError`.

If you are hosting this, it is suggested that you simply minify the JavaScript files first with a tool like https://jscompress.com/. When compressed, RuntimeFS is `<100KB`.

Do note that not all code you download from the internet will immediately work, and may require configuration. Many web projects require you to compile them locally, such as Vite projects (or require you to add a tag like `<base href="/n/my-folder/">`).

### TODO
- More optimization, and ability to export large `.cbor` files without crashes
- Basic editing of the local file system
- Console log and JS execution panel (for some cases where Inspect is disabled)
- Detailed, complete documentation
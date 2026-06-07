const SUS = [
  '/system/bin/su','/system/xbin/su','/sbin/su','/system/su',
  '/system/bin/busybox','/system/xbin/busybox'
];

function isSus(ptrPath) {
  try {
    const p = ptrPath.readCString();
    return !!p && (SUS.indexOf(p) !== -1 ||
           p.includes('/proc/mounts') ||
           p.includes('/proc/self/mounts'));
  } catch(_) { return false; }
}

function hookLibc(name, pathArgIndex) {
  const libc = 'libc.so';
  const addr = Module.findExportByName(libc, name) ||
               Module.findExportByName(null, name);
  if (!addr) return console.log('[*] Export introuvable:', name);
  Interceptor.attach(addr, {
    onEnter(args) {
      const pArg = pathArgIndex >= 0 ? args[pathArgIndex] : null;
      if (pArg && isSus(pArg)) {
        this.block = true;
        this.path = pArg.readCString();
      }
    },
    onLeave(retval) {
      if (this.block) {
        console.log('[+] Blocked', name, 'on', this.path);
        retval.replace(ptr(-1));
      }
    }
  });
  console.log('[+] Hooked', name);
}

hookLibc('open', 0);
hookLibc('openat', 1);
hookLibc('access', 0);
hookLibc('stat', 0);
hookLibc('lstat', 0);

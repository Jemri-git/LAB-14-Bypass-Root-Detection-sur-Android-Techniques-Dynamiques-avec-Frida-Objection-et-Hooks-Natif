// Hooks simples pour neutraliser des checks Java basiques
const suspiciousPaths = [
  "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su",
  "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
  "/system/bin/busybox", "/system/xbin/busybox"
];

function lc(s){ try { return (""+s).toLowerCase(); } catch(_) { return ""; } }

Java.perform(function () {
  // 1) Build.TAGS → retour propre
  try {
    const Build = Java.use('android.os.Build');
    Object.defineProperty(Build, 'TAGS', { get: function() { return 'release-keys'; } });
    console.log('[+] Build.TAGS -> release-keys');
  } catch (e) { console.log('[-] Build.TAGS hook failed:', e); }

  // 2) RootBeer (si présent)
  try {
    const RB = Java.use('com.scottyab.rootbeer.RootBeer');
    RB.isRooted.implementation = function(){
      console.log('[+] RootBeer.isRooted -> false'); return false;
    };
    if (RB.isRootedWithBusyBoxCheck)
      RB.isRootedWithBusyBoxCheck.implementation = function(){
        console.log('[+] RootBeer.isRootedWithBusyBoxCheck -> false'); return false;
      };
  } catch(e) { console.log('[*] RootBeer non présent'); }

  // 3) File.exists() → dire "non" pour chemins suspects
  try {
    const File = Java.use('java.io.File');
    File.exists.implementation = function () {
      const p = this.getAbsolutePath();
      if (suspiciousPaths.indexOf(p) !== -1) {
        console.log('[+] File.exists bypass:', p); return false;
      }
      return this.exists.call(this);
    };
  } catch (e) { console.log('[-] File.exists hook failed:', e); }

  // 4) Runtime.exec → bloquer su/which/busybox
  try {
    const Runtime = Java.use('java.lang.Runtime');
    const JString = Java.use('java.lang.String');
    const StringArray = Java.use('[Ljava.lang.String;');

    function suspicious(cmd){
      const s = lc(Array.isArray(cmd)? cmd.join(' ') : cmd);
      return s.startsWith('su') || s.includes(' which su') ||
             s.includes(' busybox') || s.includes(' su ');
    }

    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      if (suspicious(cmd)) {
        console.log('[+] Blocked Runtime.exec:', cmd);
        return this.exec(JString.$new('echo'));
      }
      return this.exec(cmd);
    };
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (arr) {
      const js = arr? Array.from(arr) : [];
      if (suspicious(js)) {
        console.log('[+] Blocked Runtime.exec:', js.join(' '));
        const repl = StringArray.$new(1); repl[0] = JString.$new('echo');
        return this.exec(repl);
      }
      return this.exec(arr);
    };
    Runtime.exec.overload('java.lang.String','[Ljava.lang.String;').implementation = function (cmd, env) {
      if (suspicious(cmd)) {
        console.log('[+] Blocked Runtime.exec:', cmd);
        return this.exec(JString.$new('echo'), env);
      }
      return this.exec(cmd, env);
    };
    Runtime.exec.overload('[Ljava.lang.String;','[Ljava.lang.String;').implementation = function (arr, env) {
      const js = arr? Array.from(arr) : [];
      if (suspicious(js)) {
        console.log('[+] Blocked Runtime.exec:', js.join(' '));
        const repl = StringArray.$new(1); repl[0] = JString.$new('echo');
        return this.exec(repl, env);
      }
      return this.exec(arr, env);
    };
    console.log('[+] Runtime.exec hooks installés');
  } catch (e) { console.log('[-] Runtime.exec hooks failed:', e); }

  console.log('[+] Bypass Java installé');
});

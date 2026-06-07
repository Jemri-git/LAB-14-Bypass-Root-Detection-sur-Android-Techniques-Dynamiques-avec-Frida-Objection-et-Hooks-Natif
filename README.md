# LAB 14 : Bypass Root Detection sur Android : Techniques Dynamiques avec Frida, Objection et Hooks Natifs

**Environnement :** Windows 11 — Genymotion Android 9.0 (Pie) x86 — Frida 17.10.1  
**Cible :** RootBeer Sample — `com.scottyab.rootbeer.sample`  
**Résultat :** 10/12 checks bypassés (limitation x86/Frida 17 sur hooks natifs)

---

## 1. Vue d'ensemble

### Contexte

Ce lab couvre le bypass de root detection via des **scripts Frida JavaScript fournis clé en main**, en suivant une progression pédagogique débutant pas à pas :

```
hello.js          → valider l'injection
bypass_root_basic.js  → neutraliser les checks Java
bypass_native.js      → neutraliser les checks C/JNI natifs
```

### Architecture

```
PC (Windows 11)                     Android (Genymotion x86)
────────────────────                ─────────────────────────
frida CLI           ←── ADB/TCP ──→ frida-server (root)
bypass_root_basic.js                  ↓ injection
bypass_native.js                   RootBeer Sample
bypass_combined.js                   ├── Couche Java (ART)
                                     └── Couche native (libc.so)
```

---

## 2. Étape 1 — Environnement et prérequis

### 2.1 Vérifications initiales

```powershell
python --version
# → Python 3.14.5

pip --version
frida --version
# → 17.10.1

adb devices
# → 192.168.206.103:5555   device
```

### 2.2 Installation Frida 

```powershell
pip install --upgrade frida frida-tools
```

> **Conseil Windows :** si `frida` n'est pas reconnu, ajouter le dossier Scripts Python au PATH :
> ```powershell
> $env:PATH += ";$env:USERPROFILE\AppData\Roaming\Python\Python314\Scripts"
> ```

---

## 3. Étape 2 — frida-server sur Genymotion

### 3.1 Déploiement (déjà effectué en Lab 10)

```powershell
# Vérifier l'architecture
adb shell getprop ro.product.cpu.abi
# → x86

# SELinux permissif
adb shell setenforce 0

# Lancer frida-server
adb shell "/data/local/tmp/frida-server -l 0.0.0.0 &"

# Forwarder les ports
adb forward tcp:27042 tcp:27042
adb forward tcp:27043 tcp:27043

# Valider
frida-ps -Uai
```

### 3.2 Résultat frida-ps -Uai
<img width="1102" height="62" alt="image" src="https://github.com/user-attachments/assets/b4cab649-6f6a-42b3-990b-2fff2f8c9d92" />

---

## 4. Étape 3 — Test d'injection avec hello.js

### 4.1 Objectif

Valider que Frida peut injecter du code dans l'app avant d'aller plus loin. C'est le test minimal obligatoire.

### 4.2 Script hello.js

```javascript
Java.perform(function () {
  console.log("[+] Script injecté: Java.perform OK");
});
```

### 4.3 Exécution

```powershell
frida -U -f com.scottyab.rootbeer.sample -l hello.js
```

> **Note :** `--no-pause` a été supprimé dans Frida 17.x — ne pas l'utiliser.

### 4.4 Résultat 

<img width="692" height="287" alt="image" src="https://github.com/user-attachments/assets/00964e09-dd67-4cd8-af3b-e78049562104" />


### 4.5 Ce que ça valide

- ✅ frida-server répond
- ✅ Frida peut spawner l'app
- ✅ `Java.perform()` s'exécute dans le runtime ART

---

## 5. Étape 4 — bypass_root_basic.js (couche Java)

### 5.1 Objectif

Neutraliser les checks de root detection implémentés en Java/Kotlin, sans toucher à la couche native C/JNI.

### 5.2 État initial de l'app — ROOTED

Avant toute instrumentation, RootBeer détecte correctement l'environnement rooté.

### 5.3 Exécution du script bypass_root_basic.js

```powershell
frida -U -f com.scottyab.rootbeer.sample -l bypass_root_basic.js
```

### 5.4 Logs obtenus

<img width="822" height="446" alt="image" src="https://github.com/user-attachments/assets/7412dc2c-5cdd-463b-9524-196de0045ee8" />

### 5.5 Résultat — 8/12

| Check | Statut |
|---|---|
| Root Management Apps | ✅ bypassé |
| Potentially Dangerous Apps | ✅ bypassé |
| Root Cloaking Apps | ✅ bypassé |
| TestKeys | ⊗ résiste |
| BusyBoxBinary | ✅ bypassé |
| SU Binary | ✅ bypassé |
| 2nd SU Binary check | ⊗ résiste |
| For RW Paths | ✅ bypassé |
| Dangerous Props | ⊗ résiste |
| Root via native check | ⊗ résiste |
| SE linux Flag Is Enabled | ✅ bypassé |
| Magisk specific checks | ✅ bypassé |

**Score : 8/12** — attendu pour la couche Java seule.
<img width="434" height="834" alt="Screenshot 2026-06-07 142748" src="https://github.com/user-attachments/assets/ceb40db3-2908-4be6-a306-1b0420ddd4f7" />


### 5.6 Pourquoi 4 checks résistent ?

- **TestKeys** — RootBeer vérifie `Build.TAGS` via une méthode supplémentaire non couverte par ce script basique
- **2nd SU Binary check** — certains chemins absents de `suspiciousPaths`
- **Dangerous Props** — lit `/proc/sys` directement en C, hors portée Java
- **Root via native check** — appels `open/access/stat` en C pur, hors portée Java

---

## 6. Étape 4.1 — bypass_native.js (couche C/JNI)

### 6.1 Objectif

Intercepter les appels POSIX bas niveau (`open`, `openat`, `access`, `stat`, `lstat`) que l'app effectue directement en C pour chercher les binaires root.

### 6.2 Exécution combinée (théorique)

```powershell
frida -U -f com.scottyab.rootbeer.sample -l bypass_root_basic.js -l bypass_native.js
```

### 6.3 Problème rencontré — Interceptor cassé sur x86/Frida 17
<img width="460" height="118" alt="image" src="https://github.com/user-attachments/assets/f901c115-ea37-4d77-9621-b31b5d32b247" />


**Diagnostic depuis la console interactive :**

```javascript
[Phone::PID::2944 ]-> Interceptor
// → {} (objet vide — existe mais sans méthodes)

[Phone::PID::2944 ]-> typeof Interceptor
// → "object"

[Phone::PID::2944 ]-> Module.findExportByName('libc.so', 'open')
// → TypeError: not a function
```

### 6.4 Cause racine

**Bug connu : Frida 17.x + Genymotion x86 + mode attach**

Le runtime natif Frida (`frida-agent`) ne s'initialise pas complètement sur les processus x86 en attach mode. `Module`, `Interceptor` et `Memory` sont des objets vides — leurs méthodes ne sont pas exposées.

| Combinaison | Interceptor |
|---|---|
| Frida 17.x + Genymotion x86 + attach | ❌ cassé |
| Frida 17.x + Genymotion x86 + spawn | ❌ cassé |
| Frida 16.x + Genymotion x86 | ✅ fonctionnel |
| Frida 17.x + vrai device arm64 | ✅ fonctionnel |

### 6.5 Solution — Script fusionné bypass_combined.js

Pour contourner le conflit entre `-l script1 -l script2`, on fusionne les deux scripts et on étend les hooks RootBeer Java pour couvrir les méthodes manquantes :

```javascript
Java.perform(function () {

  // 1) Build.TAGS
  try {
    const Build = Java.use('android.os.Build');
    Object.defineProperty(Build, 'TAGS', { get: function() { return 'release-keys'; } });
    console.log('[+] Build.TAGS -> release-keys');
  } catch(e) { console.log('[-] Build.TAGS:', e.message); }

  // 2) RootBeer — toutes les méthodes boolean
  try {
    const RB = Java.use('com.scottyab.rootbeer.RootBeer');
    const methods = [
      'isRooted','isRootedWithBusyBoxCheck','detectRootManagementApps',
      'detectPotentiallyDangerousApps','detectTestKeys','checkForBusyBoxBinary',
      'checkForSuBinary','checkSuExists','checkForRWPaths','checkDangerousProps',
      'checkRootThroughNativeCode','detectRootCloakingApps',
      'checkForMagiskBinary','checkForOverTheAirCertificates'
    ];
    methods.forEach(function(m) {
      try {
        RB[m].implementation = function() {
          console.log('[+] RootBeer.' + m + ' -> false');
          return false;
        };
      } catch(_) {}
    });
    console.log('[+] RootBeer hooks installés');
  } catch(e) { console.log('[*] RootBeer:', e.message); }

  // 3) File.exists
  try {
    const suspiciousPaths = [
      "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su",
      "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
      "/system/bin/busybox", "/system/xbin/busybox",
      "/data/local/magisk", "/sbin/magisk"
    ];
    const File = Java.use('java.io.File');
    File.exists.implementation = function () {
      const p = this.getAbsolutePath();
      if (suspiciousPaths.indexOf(p) !== -1) {
        console.log('[+] File.exists bypass:', p);
        return false;
      }
      return this.exists.call(this);
    };
    console.log('[+] File.exists hook installé');
  } catch(e) { console.log('[-] File.exists:', e.message); }

  // 4) Runtime.exec
  try {
    const Runtime = Java.use('java.lang.Runtime');
    const JString = Java.use('java.lang.String');
    function sus(s){
      s = (s||'').toLowerCase();
      return s.startsWith('su') || s.includes(' su') ||
             s.includes('busybox') || s.includes('which');
    }
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
      if (sus(cmd)) {
        console.log('[+] Blocked exec:', cmd);
        return this.exec(JString.$new('echo'));
      }
      return this.exec(cmd);
    };
    console.log('[+] Runtime.exec hook installé');
  } catch(e) { console.log('[-] Runtime.exec:', e.message); }

  // 5) SystemProperties
  try {
    const SP = Java.use('android.os.SystemProperties');
    SP.get.overload('java.lang.String').implementation = function(key) {
      if (key.indexOf('ro.debuggable') !== -1) { return '0'; }
      if (key.indexOf('ro.secure') !== -1)     { return '1'; }
      if (key.indexOf('service.adb.root') !== -1) { return '0'; }
      return this.get(key);
    };
    console.log('[+] SystemProperties hook installé');
  } catch(e) { console.log('[-] SystemProperties:', e.message); }

  console.log('[+] Bypass complet installé');
});
```

### 6.7 Résultat bypass_combined.js — 10/12

```powershell
frida -U -f com.scottyab.rootbeer.sample -l bypass_combined.js
```

```
[+] Build.TAGS -> release-keys
[+] RootBeer hooks installés
[+] File.exists hook installé
[+] Runtime.exec hook installé
[+] SystemProperties hook installé
[+] Bypass complet installé
[+] RootBeer.detectTestKeys -> false
[+] RootBeer.checkForBusyBoxBinary -> false
[+] RootBeer.checkForSuBinary -> false
[+] RootBeer.checkSuExists -> false
[+] RootBeer.checkForRWPaths -> false
[+] RootBeer.checkForMagiskBinary -> false
```

| Check | bypass_root_basic.js | bypass_combined.js |
|---|---|---|
| Root Management Apps | ✅ | ✅ |
| Potentially Dangerous Apps | ✅ | ✅ |
| Root Cloaking Apps | ✅ | ✅ |
| TestKeys | ⊗ | ✅ |
| BusyBoxBinary | ✅ | ✅ |
| SU Binary | ✅ | ✅ |
| 2nd SU Binary check | ⊗ | ✅ |
| For RW Paths | ✅ | ✅ |
| Dangerous Props | ⊗ | ⊗ |
| Root via native check | ⊗ | ⊗ |
| SE linux Flag Is Enabled | ✅ | ✅ |
| Magisk specific checks | ✅ | ✅ |
| **Score** | **8/12** | **10/12** |

<img width="516" height="876" alt="Screenshot 2026-06-07 140859" src="https://github.com/user-attachments/assets/704d9a68-22b5-4270-9f9b-6cee4b62ce71" />

### 6.9 Pourquoi 2 checks résistent encore ?

Ces 2 checks sont **100% natifs** — ils lisent directement via des appels système C, sans aucune passerelle Java :

- **Dangerous Props** — lit `/proc/sys/kernel/...` via `syscall` direct
- **Root via native check** — appels `open/access` vers `/system/xbin/su` en JNI pur

Sur Genymotion x86 + Frida 17, `Interceptor` n'est pas fonctionnel → ces checks ne peuvent pas être bypassés dans cette configuration. Sur un vrai device arm64 avec Frida 16.x, `bypass_native.js` couvrirait ces 2 cas restants.

---

## 7. Étape 5 — Objection

> ℹ️ **Déjà couvert en Lab 13** — `android root disable` → 12/12 NOT ROOTED  
> Se référer au rapport Lab 14 pour les détails.

```powershell
objection -n com.scottyab.rootbeer.sample start
# Dans la console :
android root disable
```

---

## 8. Étape 6 — Medusa

> ℹ️ **Déjà couvert en Lab 12** — module `rootbeer_detection_bypass_no_obfuscation` → 12/12 NOT ROOTED  
> Se référer au rapport Lab 12 pour les détails.

```powershell
python medusa.py -p com.scottyab.rootbeer.sample
# Dans la console :
use root_detection/rootbeer_detection_bypass_no_obfuscation
run com.scottyab.rootbeer.sample
```

---

## 9. Étape 7 — Magisk

### Quand utiliser Magisk plutôt que Frida/Objection/Medusa ?

| Critère | Frida/Objection | Magisk |
|---|---|---|
| Portée | Par app, par session | Système entier, permanent |
| Play Integrity / SafetyNet | ❌ insuffisant | ✅ avec modules adaptés |
| Propriétés kernel profondes | ❌ limité | ✅ MagiskHide Props Config |
| Plusieurs apps simultanées | À répéter pour chaque | ✅ DenyList global |
| Émulateur | ✅ compatible | ❌ incompatible Genymotion |

### Étapes résumées (vrai device uniquement)

```
1. Rooter avec Magisk (boot image patché)
2. Activer Zygisk dans les paramètres Magisk
3. Configurer DenyList (app cible + Play Services + Play Store)
4. Installer modules : Play Integrity Fix, Shamiko, MagiskHide Props Config
5. Nettoyer données Play Store/Services
6. Redémarrer et tester
```
---

## 10. Concepts clés

### 10.1 Java.perform()

`Java.perform()` est le point d'entrée obligatoire pour tout hook Java dans Frida. Il garantit que le runtime ART est prêt avant d'exécuter le code.

```javascript
Java.perform(function () {
  // Tout hook Java doit être ici
  const Build = Java.use('android.os.Build');
});
```

### 10.2 .implementation vs Object.defineProperty

Deux façons de hooker selon le type de cible :

```javascript
// Hooker une méthode
MyClass.methodName.implementation = function() {
  return false; // remplace le comportement
};

// Hooker une propriété statique
Object.defineProperty(Build, 'TAGS', {
  get: function() { return 'release-keys'; }
});
```

### 10.3 Overloads Java

Quand une méthode a plusieurs signatures, il faut spécifier la surcharge :

```javascript
// Hooker Runtime.exec(String)
Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
  return this.exec('echo');
};

// Hooker Runtime.exec(String[])
Runtime.exec.overload('[Ljava.lang.String;').implementation = function(arr) {
  // ...
};
```

### 10.4 Interceptor.attach — Hooks natifs

Pour intercepter des fonctions C/POSIX :

```javascript
const addr = Module.findExportByName('libc.so', 'open');
Interceptor.attach(addr, {
  onEnter(args) {
    const path = args[0].readCString(); // lire l'argument char*
  },
  onLeave(retval) {
    retval.replace(ptr(-1)); // simuler une erreur POSIX
  }
});
```

`ptr(-1)` simule un code d'erreur POSIX standard — l'app croit que le fichier n'existe pas.

### 10.5 Spawn vs Attach

```
Spawn  (-f) : Frida démarre l'app → hooks actifs dès le début
Attach (-p) : App déjà lancée → Frida s'y greffe
```

Sur Genymotion x86 + Frida 17, les hooks **Java** fonctionnent dans les deux modes. Les hooks **natifs** (`Interceptor`) échouent dans les deux modes — c'est une limitation de l'environnement x86.

### 10.6 Obfuscation — Énumération des classes chargées

Quand les noms de classes sont inconnus (app obfusquée) :

```javascript
Java.perform(function(){
  Java.enumerateLoadedClasses({
    onMatch: function(n){
      if (n.toLowerCase().includes('root')) console.log(n);
    },
    onComplete: function(){ console.log('done'); }
  });
});
```

### 10.7 Anti-Frida basique

Certaines apps détectent la présence de Frida. Mitigation minimale :

```javascript
Java.perform(function(){
  try {
    const Sys = Java.use('java.lang.System');
    Sys.getenv.overload('java.lang.String').implementation = function(name){
      if (name && name.toLowerCase().includes('frida')) {
        console.log('[+] Hide env', name); return null;
      }
      return this.getenv(name);
    };
  } catch(e){}
});
```

---



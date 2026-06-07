# LAB 14 : Bypass Root Detection sur Android : Techniques Dynamiques avec Frida, Objection et Hooks Natifs

**Environnement :** Windows 11 — Genymotion Android 9.0 (Pie) x86 — Frida 17.10.1  
**Cible :** RootBeer Sample — `com.scottyab.rootbeer.sample`  
**Résultat :** 10/12 checks bypassés (limitation x86/Frida 17 sur hooks natifs)

---

## Sommaire

1. [Vue d'ensemble](#1-vue-densemble)
2. [Étape 1 — Environnement et prérequis](#2-étape-1--environnement-et-prérequis)
3. [Étape 2 — frida-server sur Genymotion](#3-étape-2--frida-server-sur-genymotion)
4. [Étape 3 — Test d'injection avec hello.js](#4-étape-3--test-dinjection-avec-hellojs)
5. [Étape 4 — bypass_root_basic.js (couche Java)](#5-étape-4--bypass_root_basicjs-couche-java)
6. [Étape 4.1 — bypass_native.js (couche C/JNI)](#6-étape-41--bypass_nativejs-couche-cjni)
7. [Étape 5 — Objection](#7-étape-5--objection)
8. [Étape 6 — Medusa](#8-étape-6--medusa)
9. [Étape 7 — Magisk (hors scope)](#9-étape-7--magisk-hors-scope)
10. [Résultats et check-list](#10-résultats-et-check-list)
11. [Concepts clés](#11-concepts-clés)
12. [Comparatif des approches](#12-comparatif-des-approches)
13. [Récapitulatif des commandes](#13-récapitulatif-des-commandes)
14. [Dépannage](#14-dépannage)

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

### 2.2 Installation Frida (si nécessaire)

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

### 5.3 Script bypass_root_basic.js

```javascript
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
```

### 5.4 Exécution

```powershell
frida -U -f com.scottyab.rootbeer.sample -l bypass_root_basic.js
```

### 5.5 Logs obtenus

```
[Phone::com.scottyab.rootbeer.sample ]-> [+] Build.TAGS -> release-keys
[+] Runtime.exec hooks installés
[+] Bypass Java installé
[+] File.exists bypass: /system/bin/busybox
[+] File.exists bypass: /system/xbin/busybox
[+] File.exists bypass: /sbin/su
[+] File.exists bypass: /system/bin/su
[+] File.exists bypass: /system/xbin/su
```

> 📸 **[SCREEN 5 — Insérer ici]**  
> *Capture du terminal montrant les logs `[+]` de bypass_root_basic.js après CHECK dans l'app*

### 5.6 Résultat — 8/12

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

> 📸 **[SCREEN 6 — Insérer ici]**  
> *Capture de l'app RootBeer après bypass_root_basic.js — encore ROOTED mais avec 8 checks verts*

### 5.7 Pourquoi 4 checks résistent ?

- **TestKeys** — RootBeer vérifie `Build.TAGS` via une méthode supplémentaire non couverte par ce script basique
- **2nd SU Binary check** — certains chemins absents de `suspiciousPaths`
- **Dangerous Props** — lit `/proc/sys` directement en C, hors portée Java
- **Root via native check** — appels `open/access/stat` en C pur, hors portée Java

---

## 6. Étape 4.1 — bypass_native.js (couche C/JNI)

### 6.1 Objectif

Intercepter les appels POSIX bas niveau (`open`, `openat`, `access`, `stat`, `lstat`) que l'app effectue directement en C pour chercher les binaires root.

### 6.2 Script bypass_native.js

```javascript
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
```

### 6.3 Exécution combinée (théorique)

```powershell
frida -U -f com.scottyab.rootbeer.sample -l bypass_root_basic.js -l bypass_native.js
```

### 6.4 Problème rencontré — Interceptor cassé sur x86/Frida 17

```
[-] hookLibc failed for open : not a function
[-] hookLibc failed for openat : not a function
[-] hookLibc failed for access : not a function
[-] hookLibc failed for stat : not a function
[-] hookLibc failed for lstat : not a function
```

**Diagnostic depuis la console interactive :**

```javascript
[Phone::PID::2944 ]-> Interceptor
// → {} (objet vide — existe mais sans méthodes)

[Phone::PID::2944 ]-> typeof Interceptor
// → "object"

[Phone::PID::2944 ]-> Module.findExportByName('libc.so', 'open')
// → TypeError: not a function
```

> 📸 **[SCREEN 7 — Insérer ici]**  
> *Capture du terminal montrant les erreurs `hookLibc failed` et le diagnostic `Interceptor` / `Module.findExportByName` dans la console interactive*

### 6.5 Cause racine

**Bug connu : Frida 17.x + Genymotion x86 + mode attach**

Le runtime natif Frida (`frida-agent`) ne s'initialise pas complètement sur les processus x86 en attach mode. `Module`, `Interceptor` et `Memory` sont des objets vides — leurs méthodes ne sont pas exposées.

| Combinaison | Interceptor |
|---|---|
| Frida 17.x + Genymotion x86 + attach | ❌ cassé |
| Frida 17.x + Genymotion x86 + spawn | ❌ cassé |
| Frida 16.x + Genymotion x86 | ✅ fonctionnel |
| Frida 17.x + vrai device arm64 | ✅ fonctionnel |

### 6.6 Solution — Script fusionné bypass_combined.js

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

> 📸 **[SCREEN 8 — Insérer ici]**  
> *Capture du terminal montrant les logs de bypass_combined.js avec tous les `[+] RootBeer.xxx -> false`*

> 📸 **[SCREEN 9 — Insérer ici]**  
> *Capture de l'app RootBeer après bypass_combined.js — encore ROOTED mais avec 10 checks en vert*

### 6.8 Pourquoi 2 checks résistent encore ?

Ces 2 checks sont **100% natifs** — ils lisent directement via des appels système C, sans aucune passerelle Java :

- **Dangerous Props** — lit `/proc/sys/kernel/...` via `syscall` direct
- **Root via native check** — appels `open/access` vers `/system/xbin/su` en JNI pur

Sur Genymotion x86 + Frida 17, `Interceptor` n'est pas fonctionnel → ces checks ne peuvent pas être bypassés dans cette configuration. Sur un vrai device arm64 avec Frida 16.x, `bypass_native.js` couvrirait ces 2 cas restants.

---

## 7. Étape 5 — Objection

> ℹ️ **Déjà couvert en Lab 4** — `android root disable` → 12/12 NOT ROOTED  
> Se référer au rapport Lab 4 pour les détails.

```powershell
objection -n com.scottyab.rootbeer.sample start
# Dans la console :
android root disable
```

---

## 8. Étape 6 — Medusa

> ℹ️ **Déjà couvert en Lab 3** — module `rootbeer_detection_bypass_no_obfuscation` → 12/12 NOT ROOTED  
> Se référer au rapport Lab 3 pour les détails.

```powershell
python medusa.py -p com.scottyab.rootbeer.sample
# Dans la console :
use root_detection/rootbeer_detection_bypass_no_obfuscation
run com.scottyab.rootbeer.sample
```

---

## 9. Étape 7 — Magisk (hors scope)

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

> ⚠️ **Hors scope** : Genymotion ne supporte pas Magisk. `Strong Integrity` (matériel) n'est généralement pas contournable sans vulnérabilité spécifique.

---

## 10. Résultats et check-list

### 10.1 Check-list rapide

| Étape | Statut | Détail |
|---|---|---|
| ✅ Python et pip OK | Validé | Python 3.14.5 |
| ✅ ADB OK | Validé | `adb devices` → `device` |
| ✅ frida-server lancé | Validé | `frida-ps -Uai` liste les apps |
| ✅ hello.js injecté | Validé | `Java.perform OK` |
| ✅ bypass_root_basic.js | Validé | 8/12 checks Java bypassés |
| ⚠️ bypass_native.js | Limité | `Interceptor` cassé sur x86/Frida 17 |
| ✅ bypass_combined.js | Validé | 10/12 checks bypassés |
| ✅ Objection | Validé | 12/12 — Lab 4 |
| ✅ Medusa | Validé | 12/12 — Lab 3 |
| ➖ Magisk | Hors scope | Incompatible Genymotion |

### 10.2 Progression des scores

| Script / Outil | Score | Couverture |
|---|---|---|
| bypass_root_basic.js | 8/12 | Java uniquement |
| bypass_combined.js | 10/12 | Java étendu + SystemProperties |
| bypass_native.js | +0 (x86 limité) | Natif — non fonctionnel sur cette config |
| Objection (Lab 4) | 12/12 | Java + natif via modules intégrés |
| Medusa (Lab 3) | 12/12 | Java via réflexion |

---

## 11. Concepts clés

### 11.1 Java.perform()

`Java.perform()` est le point d'entrée obligatoire pour tout hook Java dans Frida. Il garantit que le runtime ART est prêt avant d'exécuter le code.

```javascript
Java.perform(function () {
  // Tout hook Java doit être ici
  const Build = Java.use('android.os.Build');
});
```

### 11.2 .implementation vs Object.defineProperty

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

### 11.3 Overloads Java

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

### 11.4 Interceptor.attach — Hooks natifs

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

### 11.5 Spawn vs Attach

```
Spawn  (-f) : Frida démarre l'app → hooks actifs dès le début
Attach (-p) : App déjà lancée → Frida s'y greffe
```

Sur Genymotion x86 + Frida 17, les hooks **Java** fonctionnent dans les deux modes. Les hooks **natifs** (`Interceptor`) échouent dans les deux modes — c'est une limitation de l'environnement x86.

### 11.6 Obfuscation — Énumération des classes chargées

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

### 11.7 Anti-Frida basique

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

## 12. Comparatif des approches

| Critère | bypass_root_basic.js | bypass_combined.js | Objection | Medusa |
|---|---|---|---|---|
| Écriture de code | Fourni clé en main | Fourni + adapté | ❌ aucune | ❌ aucune |
| Couverture Java | Partielle | Complète | Complète | Complète |
| Couverture native | ❌ | ❌ (x86) | ✅ intégré | ❌ |
| Score RootBeer | 8/12 | 10/12 | 12/12 | 12/12 |
| Logs détaillés | ✅ `[+]` par hook | ✅ `[+]` par hook | Partiels | Partiels |
| Valeur pédagogique | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ |

---

## 13. Récapitulatif des commandes

### Setup

```powershell
# Vérifications
python --version && frida --version && adb devices

# frida-server
adb shell setenforce 0
adb shell "/data/local/tmp/frida-server -l 0.0.0.0 &"
adb forward tcp:27042 tcp:27042

# Lister les apps
frida-ps -Uai
frida-ps -U | findstr -i rootbeer
```

### Frida — Spawn (recommandé)

```powershell
# Test minimal
frida -U -f com.scottyab.rootbeer.sample -l hello.js

# Bypass Java basique
frida -U -f com.scottyab.rootbeer.sample -l bypass_root_basic.js

# Bypass Java étendu
frida -U -f com.scottyab.rootbeer.sample -l bypass_combined.js
```

### Frida — Attach (sur app déjà lancée)

```powershell
# Trouver le PID
frida-ps -U | findstr -i rootbeer

# Attacher par PID
frida -U -p <PID> -l bypass_combined.js

# Attacher par nom
frida -U -n "RootBeer Sample" -l bypass_combined.js
```

### frida-trace — Découverte des appels natifs

```powershell
frida-trace -U -p <PID> -i "open" -i "access" -i "stat" -i "openat" -i "fopen"
frida-trace -U -p <PID> -j "*isRoot*"
```

### Console interactive Frida

```javascript
// Diagnostiquer Interceptor
typeof Interceptor
Module.findExportByName('libc.so', 'open')

// Énumérer les classes chargées
Java.perform(function(){
  Java.enumerateLoadedClasses({
    onMatch: function(n){ if(n.includes('root')) console.log(n); },
    onComplete: function(){}
  });
});
```

---

## 14. Dépannage

| Problème | Cause | Solution |
|---|---|---|
| `--no-pause` non reconnu | Supprimé dans Frida 17.x | Ne pas l'utiliser |
| `Interceptor: not a function` | Bug Frida 17 + Genymotion x86 | Utiliser Java hooks uniquement ou downgrader Frida |
| `Module.findExportByName: not a function` | Même cause | Idem |
| Deux `-l` scripts en conflit | Contexte partagé Frida 17 | Fusionner en un seul fichier |
| `frida-ps` ne liste pas l'app | frida-server arrêté | `adb shell ps \| findstr frida` puis relancer |
| App crashe au spawn | Hooks trop tôt | Essayer en attach (`-p PID`) |
| Classes RootBeer non trouvées | App non encore chargée | Déclencher CHECK dans l'app d'abord |

---

## Bilan des 5 labs

| Lab | Outil | Objectif | Score |
|---|---|---|---|
| Lab 1 | Frida | Install, déploiement frida-server, injection minimale | — |
| Lab 2 | Frida | Scripts JS custom écrits from scratch | 9/12 |
| Lab 3 | Medusa | Module `.med` prêt à l'emploi | 12/12 ✅ |
| Lab 4 | Objection | CLI interactive — `android root disable` | 12/12 ✅ |
| **Lab 5** | **Frida** | **Scripts fournis clé en main, progression pédagogique** | **10/12** |

Ces cinq labs couvrent l'ensemble des approches d'instrumentation dynamique Android disponibles. La progression logique va du contrôle maximal (Frida pur) à la simplicité maximale (Objection), en passant par la modularité (Medusa).

---

## Références

- Frida : <https://frida.re/>
- RootBeer : <https://github.com/scottyab/rootbeer>
- Objection : <https://github.com/sensepost/objection>
- Android Platform Tools (ADB) : <https://developer.android.com/tools/releases/platform-tools>
- Frida Releases : <https://github.com/frida/frida/releases>

---

*Guide rédigé le 05 juin 2026 — Lab 5 Frida Scripts — Instrumentation Dynamique Android*

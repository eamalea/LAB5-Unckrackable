
# Lab5 – Reverse Engineering: OWASP UnCrackable Level 2

This lab focuses on the **static analysis** of the `UnCrackable-Level2.apk`, an intentionally vulnerable application from the OWASP MASTG (Mobile Application Security Testing Guide).

Unlike Level 1, this application moves the core validation logic into a native library (`libfoo.so`), requiring both Java and native code analysis to uncover the secret.

---

# 🎯 Learning Objectives

- Understand how **JNI (Java Native Interface)** works in Android applications
- Decompile and analyze Java bytecode using **JADX**
- Extract native libraries (`.so`) from an APK
- Perform static analysis on native binaries using **Ghidra**
- Decode obfuscated hexadecimal strings
- Identify anti-debugging and anti-root protections
- Reconstruct the secret validation flow
- Produce a structured reverse engineering report

---

# 📦 Prerequisites

| Tool | Purpose | Download |
|------|---------|-----------|
| JADX-GUI | Decompile APK to Java source | https://github.com/skylot/jadx |
| Ghidra | Analyze native library | https://ghidra-sre.org/ |
| UnCrackable-Level2.apk | Target application | https://github.com/OWASP/owasp-mastg/tree/master/Crackmes |
| 7-Zip | Extract APK contents | https://www.7-zip.org/ |
| Python 3 | Decode hexadecimal values | https://www.python.org/ |
| ADB | Install APK on emulator | Android SDK Platform-Tools |

---

> ⚠️ **Warning**
>
> This APK is intentionally vulnerable and contains anti-debugging and anti-root protections.
>
> Perform all analysis in an isolated environment such as:
>
> - Android Emulator
> - Virtual Machine
> - Dedicated test device
>
> Do not install on a personal phone.

---

# 🧪 Step 1 – Install the Application

## Start the Emulator

Example:
- Pixel 2
- Android API 29

## Verify ADB Connection

```cmd
.\adb.exe devices
```

Expected output:

```text
emulator-5554 device
```

## Install the APK

```cmd
.\adb.exe install "UnCrackable-Level2.apk"
```

Expected output:

```text
Success
```

---

# 🔍 Step 2 – Static Analysis with JADX

## Launch JADX

```cmd
jadx-gui UnCrackable-Level2.apk
```

---

## 2.1 Analyze `AndroidManifest.xml`

![Manifest Analysis](images/lab5-1.png)

**Figure 1:** AndroidManifest.xml showing package name, main activity, and SDK versions.

### Key Observations

- Package name:
  ```text
  owasp.mstg.uncrackable2
  ```

- Main activity:
  ```text
  sg.vantagepoint.uncrackable2.MainActivity
  ```

- SDK versions:
  - `minSdkVersion = 19`
  - `targetSdkVersion = 28`

- No dangerous permissions requested

---

![Full Manifest](images/lab5-2.png)

**Figure 2:** Full manifest confirming a single activity and no exported components.

---

## 2.2 Analyze `MainActivity`

![MainActivity Decompiled](images/lab5-03.png)

**Figure 3:** Decompiled `MainActivity` showing validation logic.

### Native Library Loading

```java
static {
    System.loadLibrary("foo");
}
```

The application loads the native library:

```text
libfoo.so
```

This library contains the core verification logic.

---

### Verification Method

```java
public void verify(View view) {
    String str = this.editText.getText().toString();
    AlertDialog alertDialogCreate = new AlertDialog.Builder(this).create();

    if (this.m.a(str)) {
        alertDialogCreate.setTitle("Success!");
        alertDialogCreate.setMessage("This is the correct secret.");
    } else {
        alertDialogCreate.setTitle("Nope...");
        alertDialogCreate.setMessage("That's not it. Try again.");
    }

    alertDialogCreate.show();
}
```

---

## 2.3 Anti-Debug & Anti-Root Protections

The application implements multiple protections:

### Root Detection

Methods:
- `b.a()`
- `b.b()`
- `b.c()`

These check:
- `su` binary
- Root-related files
- Dangerous system properties

---

### Debuggable Build Detection

```java
a.a(getApplicationContext())
```

Checks whether:

```xml
android:debuggable="true"
```

---

### Runtime Debugger Detection

An `AsyncTask` continuously checks:

```java
Debug.isDebuggerConnected()
```

Frequency:

```text
Every 100ms
```

---

## 2.4 Analyze `CodeCheck`

![CodeCheck Class](images/lab5-4.png)

**Figure 4:** `CodeCheck` class containing the native method declaration.

```java
public class CodeCheck {

    private native boolean bar(byte[] bArr);

    public boolean a(String str) {
        return bar(str.getBytes());
    }
}
```

### Key Observation

The verification logic is implemented natively through:

```java
native boolean bar(byte[])
```

The actual implementation resides inside:

```text
libfoo.so
```

---

# 📦 Step 3 – Extract the Native Library

An APK is simply a ZIP archive.

Using **7-Zip**, open the APK and navigate to:

```text
/lib/x86/libfoo.so
```

or

```text
/lib/armeabi-v7a/libfoo.so
```

Extract the version matching your emulator architecture.

---

### Important Note

```java
System.loadLibrary("foo")
```

Automatically resolves to:

```text
libfoo.so
```

---

# 🧠 Step 4 – Native Analysis with Ghidra

---

## 4.1 Import `libfoo.so`

1. Create a new Ghidra project
2. Import `libfoo.so`
3. Run automatic analysis

![Ghidra Project](images/lab5-5.png)

**Figure 5:** Ghidra project with `libfoo.so` loaded.

---

## 4.2 Locate JNI Function

Navigate to:

```text
Symbol Tree → Functions
```

Locate:

```text
Java_sg_vantagepoint_uncrackable2_CodeCheck_bar
```

This is the JNI implementation of:

```java
CodeCheck.bar()
```

---

![Disassembly](images/lab5-6.png)

**Figure 6:** Ghidra disassembly view.

---

![Decompiler Output](images/lab5-7.png)

**Figure 7:** Decompiled function showing hardcoded hexadecimal chunks.

---

## Decompiled Logic

```c
int local_18;
local_18 = *(int *)(in_GS_OFFSET + 0x14);

if (DAT_00014008 == '\x01') {

    local_30 = 0x6e616854;
    local_2c = 0x6620736b;
    local_28 = 0x6120726f;
    local_24 = 0x74206c6c;
    local_20 = 0x6568;
    local_1e = 0x73696620;
    local_1a = 0x68;

    _s1 = (char *)(**(code **)(*param_1 + 0x2e0))(param_1, param_3);
    iVar1 = (**(code **)(*param_1 + 0x2ac))(param_1, param_3);

    if (iVar1 == 0x17) {
        iVar1 = strncmp(_s1, (char *)&local_30, 0x17);

        if (iVar1 == 0) {
            uVar2 = 1;
            goto LAB_00011009;
        }
    }
}

uVar2 = 0;
```

---

## Key Findings

### Input Length Check

```c
iVar1 == 0x17
```

Expected length:

```text
23 characters
```

---

### Hardcoded Secret

The hexadecimal values stored in local variables form the secret.

Because the system architecture is **little-endian**, bytes must be reversed.

---

# 🧩 Step 5 – Decode the Secret

Example conversion:

```text
0x6e616854
```

Little-endian bytes:

```text
54 68 61 6e
```

ASCII result:

```text
Than
```

---

Continue decoding all chunks.

Final reconstructed string:

```text
Thanks for all the fish
```

This is the secret expected by the application.

---

# ✅ Step 6 – Dynamic Validation

1. Launch the application
2. Enter:

```text
Thanks for all the fish
```

3. Click **VERIFY**

---

![Success Dialog](images/lab5-8.png)

**Figure 8:** Success message confirming the correct secret.

Expected result:

```text
Success! This is the correct secret.
```

---

# 📊 Complete Verification Flow

```text
User enters text in EditText
          ↓
verify() in MainActivity
          ↓
CodeCheck.a(String str)
          ↓
str.getBytes()
          ↓
CodeCheck.bar(byte[])  [Native]
          ↓
JNI → libfoo.so
          ↓
Java_sg_vantagepoint_uncrackable2_CodeCheck_bar()
          ↓
Length check == 23
          ↓
strncmp(input, "Thanks for all the fish", 23)
          ↓
Return 1 (success) or 0 (failure)
```

---

# 📋 Vulnerability Summary

| Vulnerability | Location | Severity | Description |
|---|---|---|---|
| Hardcoded Secret in Native Code | `libfoo.so` | Critical | Secret stored directly in native binary as hexadecimal values |
| Anti-Debug / Anti-Root Bypass | `MainActivity` | Medium | Protections can be bypassed using Frida, patching, or hooking |
| Predictable JNI Naming | `libfoo.so` | Low | JNI naming convention makes native methods easy to locate |

---

# ✅ Validation Checklist

- [x] APK installed successfully via ADB
- [x] AndroidManifest.xml analyzed
- [x] MainActivity decompiled
- [x] Anti-debug protections identified
- [x] `libfoo.so` extracted
- [x] JNI function located in Ghidra
- [x] Secret reconstructed
- [x] Secret validated dynamically
- [x] Documentation completed

---

# 🧹 Cleanup

Uninstall the application:

```cmd
.\adb.exe uninstall owasp.mstg.uncrackable2
```

Delete:
- Extracted APK files
- Native libraries
- Temporary analysis files

Close:
- Ghidra
- JADX

---

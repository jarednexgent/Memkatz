# Memkatz

[![memkatz-logo.png](https://i.postimg.cc/RF5T6WRw/memkatz-logo.png)](https://postimg.cc/bGgn4N4v)

#### Encrypted Reflective Mimikatz Loader

Memkatz is a post-exploitation tool that embeds an encrypted `mimikatz.exe` binary in its PE resource section. At runtime, it decrypts and reflectively loads the payload into memory, launching it after a short delay to evade memory scanners.

---

### Features

- Encrypted `mimikatz.exe` stored in the `.rsrc` section  
- In-memory decryption and execution  
- Configurable startup delay to bypass memory scanners    
- Supports original Mimikatz command-line syntax and flags    

---

### Usage

```cmd
Memkatz.exe [MimikatzCommand]
```

[![memkatz.png](https://i.postimg.cc/qBjffypN/memkatz.png)](https://postimg.cc/ThLNgyLx)

---

### Configuration

Before building, you can tune Memkatz's behavior by editing the globals at the top of `main.c`.

```c
DWORD g_DelayTime = 5000; // Execution delay in milliseconds
BOOL g_Verbose = FALSE; // Set to TRUE to enable verbose output
BOOL g_PrintBanner = TRUE; // Set to FALSE to disable the banner
```

---

### Build

**Visual Studio**  
1. Open `memkatz.sln` in Visual Studio  
2. Set **Configuration** to `Release` and **Platform** to `x64`  
3. Go to **Project → Properties** and configure:  
   - **C/C++ → Code Generation**  
     - Runtime Library: Multi-threaded (/MT)  
     - Enable C++ Exceptions: No  
   - **C/C++ → Optimization → Whole Program Optimization:** No  
   - **Linker → Debugging → Generate Debug Info:** No  
   - **Linker → Manifest → Generate Manifest:** No  
4. Build the solution.

---

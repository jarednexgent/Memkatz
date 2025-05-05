# Memkatz

#### In-Memory Encrypted Mimikatz Loader

Memkatz is a post-exploitation tool that embeds an encrypted `mimikatz.exe` in its PE resource section, decrypts it in memory at runtime, and launches it after a small delay to evade memory scanners.

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


Execution delay can be set (in milliseconds) via the `g_DelayTime` global variable. 

Verbose output can be enabled by setting `g_Verbose` to `TRUE`. 

Banner printing can be disabled by setting `g_PrintBanner` to `FALSE`.

---

### Build

**Visual Studio**  
1. Open `memkatz.sln` in Visual Studio  
2. Set **Configuration** to `Release` and **Platform** to `x64`  
3. Project Properties → C/C++ → Code Generation  
   - Runtime Library: Multi-threaded (/MT)  
   - Enable C++ Exceptions: No  
4. C/C++ → Optimization → Whole Program Optimization: No  
5. Linker → Debugging → Generate Debug Info: No  
6. Linker → Manifest → Generate Manifest: No  
7. Build the solution
---

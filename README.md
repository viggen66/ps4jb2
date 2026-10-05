# PS4jb2 — Enhanced Exploit Race Condition Mitigation

> An enhanced fork of **Sleirsgoevy's PS4jb2** with improved race-condition reliability, multi-core spray strategy, and safer cleanup.

<p align="center">
  <a href="https://viggen66.github.io/Webhost/">
    <img src="https://img.shields.io/badge/Website-viggen66.github.io-blue?style=for-the-badge&logo=github" alt="Website">
  </a>
  <img src="https://img.shields.io/badge/Language-C-blue?style=for-the-badge&logo=c" alt="Language">
  <img src="https://img.shields.io/badge/Platform-PS4-black?style=for-the-badge&logo=playstation" alt="Platform">
  <img src="https://img.shields.io/badge/Status-Research-orange?style=for-the-badge" alt="Status">
</p>

---

## ✨ Enhancements

This version builds on the original **PS4jb2** exploit by reinforcing the race-condition window and hardening the overall reliability of the jailbreak.

### 🧠 Core Improvements

| # | Feature | Description |
|---|---------|-------------|
| 1 | **CPU Pinning** | Each critical thread is bound to a specific core to reduce scheduler noise and improve race timing determinism. |
| 2 | **Multi-Core Malloc Spray** | Malloc sprays run across all available cores, increasing the chance of reclaiming freed memory during the UAF window. |
| 3 | **Gated Userland ROP** | The userland ROP chain executes **only** after `trigger_uaf()`, `fake_pktopts()`, and IDT corruption have all succeeded. |
| 4 | **Memory Cleanup** | Kernel and userland structures are properly torn down after a successful exploit. |
| 5 | **Safety Exit** | A guarded exit path preserves OS stability even if the exploit partially fails. |

### ⚙️ Technical Hardening

- 🧩 **Advanced heap grooming** and **targeted defragmentation**
- 🔌 **Clean socket caching** and **dirty FD management**
- 🚀 **Multi-core payload dispatch** for stability
- 📦 **Compact, self-contained C implementation**

---

## 🔗 Links

- 🌐 **Project site:** [viggen66.github.io/Webhost](https://viggen66.github.io/Webhost/)
- 📖 **Original project:** [Sleirsgoevy / PS4jb2](https://github.com/Sleirsgoevy)

---

<p align="center">
  <sub>Maintained by <a href="https://viggen66.github.io/Webhost/">viggen66</a> · Based on work by Sleirsgoevy</sub>
</p>

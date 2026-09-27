# Memory evidence record

Status: reviewed

The Memory detector asks whether this process's own code and mappings show signs of in-process hooking or injected code. Findings describe this process only.

## Signals

### Symbol resolution and entry prologues

- Observable signal: where dlsym resolves sensitive libc and linker symbols, and the first bytes at those entry points.
- Producing subsystem: the dynamic linker and the mapped libc and linker images in this process.
- Mechanism: a PLT or GOT hook resolves the symbol outside its module; an inline hook replaces the prologue with a branch or a load-and-branch trampoline.
- References: kernel/common Documentation/filesystems/proc.rst for /proc/self/maps; bionic linker/linker_namespaces.h for the loader's namespaces. Discovery only for the prologue byte patterns, which are the probe's instruction heuristics.
- Applicability: resolution checks on every ABI; entry byte checks only on arm64 and x86_64.
- Visibility limits: dlopen(nullptr) can fail; other ABIs report the entry check as unsupported.
- Result states: mismatch, hook-like, jump entry, clean, unavailable, unsupported ABI.
- Interpretation: an escaped symbol or branch prologue is danger; a trampoline-style entry alone is review.

### Mappings, file-backed code and loader visibility

- Observable signal: writable or anonymous executable mappings, dirty or swapped executable system pages, executable memfd, ashmem, deleted libraries or /dev/zero, modules visible to maps but not to dl_iterate_phdr, and a remapped or unusually based [vdso].
- Producing subsystem: the kernel's view of this process's address space.
- Mechanism: injected code usually needs anonymous or writable executable memory or hides its loader entry.
- References: kernel/common Documentation/filesystems/proc.rst (maps and smaps fields such as Private_Dirty and Swap, and the [vdso] mapping). ARM32 compat maps were read from kernel/common arch/arm64/kernel/vdso.c, arch/arm64/include/asm/elf.h and arch/arm64/Kconfig at deprecated/android-4.19 280f881918f4355defc34f34f7bf0b7308597b7a (Linux 4.19.132). With CONFIG_COMPAT_VDSO off, aarch32_sigreturn_setup installs one [sigpage] as VM_READ|VM_EXEC|VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC (procfs r-xp) and COMPAT_ARCH_DLINFO is empty, so no AT_SYSINFO_EHDR is emitted. CONFIG_COMPAT_VDSO defaults to y only when a 32-bit compat toolchain is configured; that build maps [vdso] and does emit AT_SYSINFO_EHDR. bionic libc/bionic/getauxval.cpp at android13-d1-release 09aa96393693e5e623eaf197b42f81a2282dfa58, unchanged through android-13.0.0_r83, returns 0 and sets ENOENT for a missing key, returns a stored 0 without ENOENT, and faults if auxv is still null. kernel.org v4.19.188 arch/arm64/kernel/vdso.c maps [vectors] and has no [sigpage], and its COMPAT_ARCH_DLINFO is also empty. Native ARM in kernel/common arch/arm/kernel/process.c installs [sigpage] with the same permission bits and emits AT_SYSINFO_EHDR only under CONFIG_VDSO. The Redmi 23028RN4DG 4.19.188 vendor tree was not found and was not reviewed.
- Applicability: every ABI and release for the mapping, file and loader checks. A missing [vdso] is treated as the normal signal page only for a process compiled as 32-bit ARM (__arm__ and not LP64) whose maps have no [vdso], exactly one private executable non-writable [sigpage] spanning one 4K, 16K or 64K page, and an absent or zero AT_SYSINFO_EHDR. A present [vdso] keeps the writable and nonzero base checks on every ABI. Kernels with CONFIG_COMPAT_VDSO, and 32-bit ARM kernels with CONFIG_VDSO, still have a [vdso].
- Visibility limits: ART's JIT legitimately creates anonymous executable code; the repository removes that known case. The signal-page result is diagnostic evidence from this process's maps and auxv. It does not show that the page is untampered, and the reviewed tree is ACK 4.19.132 rather than the reported device kernel. getauxval cannot separate a missing AT_SYSINFO_EHDR from an empty auxv vector.
- Result states: anomaly, review, clean.
- Interpretation: writable or anonymous executable code outside ART is danger; swapped executable pages are review. An unexpected [vdso] count stays a high finding outside that narrow ARM32 signal page, which sets neither remapped nor unusual base. A writable [vdso] stays a high finding. A nonzero AT_SYSINFO_EHDR that disagrees with the [vdso] base stays a medium finding. The signal-page address is not compared with AT_SYSINFO_EHDR.

### Signal handlers

- Observable signal: the handlers installed for SIGTRAP, SIGBUS, SIGSEGV and SIGILL.
- Producing subsystem: the kernel's per-process signal actions.
- Mechanism: hooking and instrumentation frameworks install handlers that point into anonymous memory.
- References: Discovery only: the handler heuristics follow observed Frida and hook framework behaviour.
- Applicability: every ABI.
- Visibility limits: legitimate crash reporters install handlers too, which is why only suspicious targets count.
- Result states: detected, review, clean.
- Interpretation: handlers in anonymous or loader-suspicious memory are review or danger by target.

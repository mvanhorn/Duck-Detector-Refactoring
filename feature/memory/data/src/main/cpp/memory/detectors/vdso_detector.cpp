/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "memory/detectors/vdso_detector.h"

#if defined(__linux__)
#include <sys/auxv.h>
#endif

#include <sstream>

namespace duckdetector::memory {
    namespace {

        // aarch32_sigreturn_setup maps exactly one PAGE_SIZE. arm64 page sizes are 4K, 16K, or 64K.
        bool is_single_page(std::uintptr_t start, std::uintptr_t end) {
            if (end <= start || (start % 0x1000U) != 0U) {
                return false;
            }
            const std::uintptr_t length = end - start;
            return length == 0x1000U || length == 0x4000U || length == 0x10000U;
        }

        // VM_READ | VM_EXEC | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC, with no VM_WRITE or VM_MAYSHARE.
        // procfs shows that as r-xp. VM_MAYWRITE only allows a later mprotect, so a writable view is
        // not the installed page.
        bool is_installed_signal_page(const MapEntry &entry) {
            return is_single_page(entry.start, entry.end) &&
                   entry.readable &&
                   !entry.writable &&
                   entry.executable &&
                   entry.private_mapping;
        }

        bool has_single_installed_signal_page(const std::vector<MapEntry> &maps) {
            const MapEntry *installed = nullptr;
            int count = 0;
            for (const MapEntry &entry: maps) {
                if (entry.path != "[sigpage]") {
                    continue;
                }
                ++count;
                installed = &entry;
            }
            return count == 1 && installed != nullptr && is_installed_signal_page(*installed);
        }

    }  // namespace

    VdsoSignals detect_vdso_anomalies(
            const std::vector<MapEntry> &maps,
            std::uintptr_t auxv_base,
            bool arm32_process
    ) {
        VdsoSignals signals;
        std::vector<MapEntry> vdso_entries;
        for (const MapEntry &entry: maps) {
            if (entry.path == "[vdso]") {
                vdso_entries.push_back(entry);
            }
        }

        if (vdso_entries.size() != 1U) {
            // Without CONFIG_COMPAT_VDSO, ACK 4.19 maps one [sigpage] for an AArch32 process and
            // leaves COMPAT_ARCH_DLINFO empty, so AT_SYSINFO_EHDR is absent. context.vdso holds the
            // signal-page address in that configuration and is not published, so this path never
            // compares the two. A real [vdso] stays on the checks below. Anything other than this
            // one page keeps the count finding, including a writable or duplicated signal page.
            const bool signal_page_instead_of_vdso =
                    arm32_process &&
                    vdso_entries.empty() &&
                    auxv_base == 0 &&
                    has_single_installed_signal_page(maps);
            if (!signal_page_instead_of_vdso) {
                signals.remapped = true;
                std::ostringstream detail;
                detail << "Expected 1 [vdso] mapping but saw " << vdso_entries.size();
                signals.findings.push_back(
                        Finding{
                                .section = "VDSO",
                                .category = "VDSO",
                                .label = "Unexpected [vdso] mapping count",
                                .detail = detail.str(),
                                .severity = FindingSeverity::kHigh,
                        }
                );
            }
            return signals;
        }

        const MapEntry &entry = vdso_entries.front();
        if (entry.writable) {
            signals.remapped = true;
            std::ostringstream detail;
            detail << "[vdso] is writable at 0x" << std::hex << entry.start << "-0x" << entry.end;
            signals.findings.push_back(
                    Finding{
                            .section = "VDSO",
                            .category = "VDSO",
                            .label = "Writable [vdso] mapping",
                            .detail = detail.str(),
                            .severity = FindingSeverity::kHigh,
                    }
            );
        }

        if (auxv_base != 0 && auxv_base != entry.start) {
            signals.unusual_base = true;
            std::ostringstream detail;
            detail << "AT_SYSINFO_EHDR=0x" << std::hex << auxv_base
                   << " but [vdso] starts at 0x" << entry.start;
            signals.findings.push_back(
                    Finding{
                            .section = "VDSO",
                            .category = "VDSO",
                            .label = "vDSO base mismatch",
                            .detail = detail.str(),
                            .severity = FindingSeverity::kMedium,
                    }
            );
        }

        return signals;
    }

    VdsoSignals detect_vdso_anomalies(const std::vector<MapEntry> &maps) {
#if defined(__linux__)
        // Android 13 getauxval returns 0 and sets ENOENT when AT_SYSINFO_EHDR is absent. That is
        // the normal compat result when COMPAT_ARCH_DLINFO is empty, and a stored 0 returns 0
        // without ENOENT. A still-null auxv pointer faults inside Bionic instead of returning an
        // error, so there is no failure value to keep out of the fallback. The signal-page shape
        // is what stops a zero auxv by itself from looking normal.
        const auto auxv_base = static_cast<std::uintptr_t>(::getauxval(AT_SYSINFO_EHDR));
#else
        // Host regression builds compile this file to call the overload. Android is Linux.
        const auto auxv_base = static_cast<std::uintptr_t>(0);
#endif
#if defined(__arm__) && !defined(__aarch64__) && !defined(__LP64__)
        constexpr bool arm32_process = true;
#else
        constexpr bool arm32_process = false;
#endif
        return detect_vdso_anomalies(maps, auxv_base, arm32_process);
    }

}  // namespace duckdetector::memory

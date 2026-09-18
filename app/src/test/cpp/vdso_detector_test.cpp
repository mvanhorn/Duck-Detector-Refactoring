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

#include <sys/auxv.h>

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

    unsigned long g_at_sysinfo_ehdr = 0;
    int g_failures = 0;

    void check(const char *file, int line, const char *expr, const bool ok) {
        if (!ok) {
            std::cerr << file << ':' << line << ": CHECK failed: " << expr << '\n';
            ++g_failures;
        }
    }

#define CHECK(cond) check(__FILE__, __LINE__, #cond, static_cast<bool>(cond))

    duckdetector::memory::MapEntry make_entry(
            const std::uintptr_t start,
            const std::uintptr_t end,
            const bool readable,
            const bool writable,
            const bool executable,
            const char *path
    ) {
        return duckdetector::memory::MapEntry{
                .start = start,
                .end = end,
                .readable = readable,
                .writable = writable,
                .executable = executable,
                .private_mapping = true,
                .inode = 0,
                .path = path,
        };
    }

    const duckdetector::memory::MapEntry kHeap = make_entry(
            0x20000, 0x30000, true, true, false, "[heap]");
    const duckdetector::memory::MapEntry kReadonlyVdso = make_entry(
            0xAE0000, 0xAE1000, true, false, true, "[vdso]");
    const duckdetector::memory::MapEntry kWritableVdso = make_entry(
            0xAE0000, 0xAE1000, true, true, true, "[vdso]");
    const duckdetector::memory::MapEntry kReadonlySigpage = make_entry(
            0x10000, 0x11000, true, false, true, "[sigpage]");
    const duckdetector::memory::MapEntry kWritableSigpage = make_entry(
            0x10000, 0x11000, true, true, true, "[sigpage]");
    const duckdetector::memory::MapEntry kSecondSigpage = make_entry(
            0x12000, 0x13000, true, false, true, "[sigpage]");
    const duckdetector::memory::MapEntry kSecondVdso = make_entry(
            0xAF0000, 0xAF1000, true, false, true, "[vdso]");
    const duckdetector::memory::MapEntry kVdsoSubstring = make_entry(
            0xB00000, 0xB01000, true, false, true, "[vdso] (deleted)");
    const duckdetector::memory::MapEntry kSigpageSubstring = make_entry(
            0xB10000, 0xB11000, true, false, true, "anon[sigpage]");

    void expect_count_anomaly(
            const duckdetector::memory::VdsoSignals &signals,
            const std::size_t expected_count
    ) {
        CHECK(signals.remapped);
        CHECK(!signals.unusual_base);
        CHECK(signals.findings.size() == 1U);
        if (signals.findings.empty()) {
            return;
        }
        CHECK(signals.findings[0].section == "VDSO");
        CHECK(signals.findings[0].category == "VDSO");
        CHECK(signals.findings[0].label == "Unexpected [vdso] mapping count");
        CHECK(signals.findings[0].severity == duckdetector::memory::FindingSeverity::kHigh);
        const std::string expected_detail =
                "Expected 1 [vdso] mapping but saw " + std::to_string(expected_count);
        CHECK(signals.findings[0].detail == expected_detail);
    }

    void expect_clean(const duckdetector::memory::VdsoSignals &signals) {
        CHECK(signals.findings.empty());
        CHECK(!signals.remapped);
        CHECK(!signals.unusual_base);
    }

    void test_sigpage_fallback_readonly_zero_auxv() {
        g_at_sysinfo_ehdr = 0;
        const auto signals = duckdetector::memory::detect_vdso_anomalies(
                {kReadonlySigpage, kHeap});
#if defined(__arm__)
        expect_clean(signals);
#else
        expect_count_anomaly(signals, 0);
#endif
    }

    void test_sigpage_fallback_writable_zero_auxv() {
        g_at_sysinfo_ehdr = 0;
        const auto signals = duckdetector::memory::detect_vdso_anomalies(
                {kWritableSigpage, kHeap});
#if defined(__arm__)
        CHECK(signals.remapped);
        CHECK(!signals.unusual_base);
        CHECK(signals.findings.size() == 1U);
        if (signals.findings.empty()) {
            return;
        }
        CHECK(signals.findings[0].section == "VDSO");
        CHECK(signals.findings[0].category == "VDSO");
        CHECK(signals.findings[0].label == "Writable [sigpage] mapping");
        CHECK(signals.findings[0].severity == duckdetector::memory::FindingSeverity::kHigh);
        CHECK(signals.findings[0].detail.find("[sigpage]") != std::string::npos);
        CHECK(signals.findings[0].detail.find("writable") != std::string::npos);
        CHECK(signals.findings[0].detail.find("0x10000") != std::string::npos);
        CHECK(signals.findings[0].detail.find("0x11000") != std::string::npos);
#else
        expect_count_anomaly(signals, 0);
#endif
    }

    void test_missing_vdso_without_sigpage() {
        g_at_sysinfo_ehdr = 0;
        expect_count_anomaly(duckdetector::memory::detect_vdso_anomalies({kHeap}), 0);
    }

    void test_missing_vdso_with_multiple_sigpages() {
        g_at_sysinfo_ehdr = 0;
        expect_count_anomaly(
                duckdetector::memory::detect_vdso_anomalies(
                        {kReadonlySigpage, kSecondSigpage, kHeap}),
                0);
    }

    void test_sigpage_only_with_nonzero_auxv() {
        g_at_sysinfo_ehdr = 0xAE0000;
        expect_count_anomaly(
                duckdetector::memory::detect_vdso_anomalies({kReadonlySigpage, kHeap}),
                0);
    }

    void test_single_readonly_vdso_matching_auxv() {
        g_at_sysinfo_ehdr = 0xAE0000;
        expect_clean(duckdetector::memory::detect_vdso_anomalies({kReadonlyVdso, kHeap}));
    }

    void test_single_readonly_vdso_matching_auxv_with_sigpage() {
        g_at_sysinfo_ehdr = 0xAE0000;
        expect_clean(duckdetector::memory::detect_vdso_anomalies(
                {kReadonlyVdso, kReadonlySigpage, kHeap}));
    }

    void test_single_writable_vdso() {
        g_at_sysinfo_ehdr = 0xAE0000;
        const auto signals = duckdetector::memory::detect_vdso_anomalies(
                {kWritableVdso, kHeap});
        CHECK(signals.remapped);
        CHECK(!signals.unusual_base);
        CHECK(signals.findings.size() == 1U);
        if (signals.findings.empty()) {
            return;
        }
        CHECK(signals.findings[0].label == "Writable [vdso] mapping");
        CHECK(signals.findings[0].severity == duckdetector::memory::FindingSeverity::kHigh);
        CHECK(signals.findings[0].detail.find("[vdso]") != std::string::npos);
    }

    void test_nonzero_auxv_mismatch() {
        g_at_sysinfo_ehdr = 0xBB0000;
        const auto signals = duckdetector::memory::detect_vdso_anomalies(
                {kReadonlyVdso, kHeap});
        CHECK(!signals.remapped);
        CHECK(signals.unusual_base);
        CHECK(signals.findings.size() == 1U);
        if (signals.findings.empty()) {
            return;
        }
        CHECK(signals.findings[0].label == "vDSO base mismatch");
        CHECK(signals.findings[0].severity == duckdetector::memory::FindingSeverity::kMedium);
        CHECK(signals.findings[0].detail.find("AT_SYSINFO_EHDR=0xbb0000") != std::string::npos);
        CHECK(signals.findings[0].detail.find("[vdso] starts at 0xae0000") != std::string::npos);
    }

    void test_single_vdso_with_zero_auxv() {
        g_at_sysinfo_ehdr = 0;
        expect_clean(duckdetector::memory::detect_vdso_anomalies({kReadonlyVdso, kHeap}));
    }

    void test_multiple_vdsos_with_sigpage() {
        g_at_sysinfo_ehdr = 0;
        expect_count_anomaly(
                duckdetector::memory::detect_vdso_anomalies(
                        {kReadonlyVdso, kSecondVdso, kReadonlySigpage, kHeap}),
                2);
    }

    void test_mapping_names_match_exactly() {
        g_at_sysinfo_ehdr = 0;
        const auto signals = duckdetector::memory::detect_vdso_anomalies(
                {kVdsoSubstring, kSigpageSubstring, kReadonlySigpage, kHeap});
#if defined(__arm__)
        expect_clean(signals);
#else
        expect_count_anomaly(signals, 0);
#endif
    }

    void test_substring_names_alone_are_not_vdso_or_sigpage() {
        g_at_sysinfo_ehdr = 0;
        expect_count_anomaly(
                duckdetector::memory::detect_vdso_anomalies(
                        {kVdsoSubstring, kSigpageSubstring, kHeap}),
                0);
    }

    const char *compilation_target() {
#if defined(__arm__)
        return "ARM32";
#elif defined(__aarch64__)
        return "AArch64";
#elif defined(__i386__)
        return "x86";
#elif defined(__x86_64__)
        return "x86_64";
#else
        return "unknown";
#endif
    }

}  // namespace

extern "C" unsigned long getauxval(unsigned long type) {
    if (type == AT_SYSINFO_EHDR) {
        return g_at_sysinfo_ehdr;
    }
    return 0;
}

int main() {
    std::cout << "vdso_detector_test compilation target: " << compilation_target() << '\n';

    test_sigpage_fallback_readonly_zero_auxv();
    test_sigpage_fallback_writable_zero_auxv();
    test_missing_vdso_without_sigpage();
    test_missing_vdso_with_multiple_sigpages();
    test_sigpage_only_with_nonzero_auxv();
    test_single_readonly_vdso_matching_auxv();
    test_single_readonly_vdso_matching_auxv_with_sigpage();
    test_single_writable_vdso();
    test_nonzero_auxv_mismatch();
    test_single_vdso_with_zero_auxv();
    test_multiple_vdsos_with_sigpage();
    test_mapping_names_match_exactly();
    test_substring_names_alone_are_not_vdso_or_sigpage();

    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "All vdso detector checks passed\n";
    return 0;
}

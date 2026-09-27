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

#include <cstdio>
#include <string>
#include <vector>

namespace {

    using duckdetector::memory::Finding;
    using duckdetector::memory::FindingSeverity;
    using duckdetector::memory::MapEntry;
    using duckdetector::memory::VdsoSignals;
    using duckdetector::memory::detect_vdso_anomalies;

    int g_failures = 0;

    MapEntry mapping(
            std::uintptr_t start,
            std::uintptr_t end,
            bool readable,
            bool writable,
            bool executable,
            bool private_mapping,
            const char *path
    ) {
        MapEntry entry;
        entry.start = start;
        entry.end = end;
        entry.readable = readable;
        entry.writable = writable;
        entry.executable = executable;
        entry.private_mapping = private_mapping;
        entry.path = path;
        return entry;
    }

    MapEntry vdso_page(std::uintptr_t start, bool writable) {
        return mapping(start, start + 0x1000U, true, writable, true, true, "[vdso]");
    }

    MapEntry signal_page(std::uintptr_t start, std::uintptr_t length, bool writable) {
        return mapping(start, start + length, true, writable, true, true, "[sigpage]");
    }

    void fail(const std::string &name) {
        std::fprintf(stderr, "FAIL %s\n", name.c_str());
        ++g_failures;
    }

    bool has_finding(
            const VdsoSignals &signals,
            FindingSeverity severity,
            const char *label
    ) {
        for (const Finding &finding: signals.findings) {
            if (finding.section == "VDSO" &&
                finding.category == "VDSO" &&
                finding.severity == severity &&
                finding.label == label) {
                return true;
            }
        }
        return false;
    }

    void expect_clean(const VdsoSignals &signals, const std::string &name) {
        if (signals.remapped || signals.unusual_base || !signals.findings.empty()) {
            fail(name + " expected a clean result");
        }
    }

    void expect_count_anomaly(const VdsoSignals &signals, const std::string &name) {
        if (!signals.remapped) {
            fail(name + " expected remapped");
        }
        if (signals.unusual_base) {
            fail(name + " used a signal page as a vDSO base");
        }
        if (!has_finding(signals, FindingSeverity::kHigh, "Unexpected [vdso] mapping count")) {
            fail(name + " expected the high count finding");
        }
        if (signals.findings.size() != 1U) {
            fail(name + " expected only the count finding");
        }
    }

    std::vector<MapEntry> reported_shape() {
        return {signal_page(0x70000000U, 0x1000U, false)};
    }

    void test_arm32_signal_page_without_vdso_is_clean() {
        const VdsoSignals signals = detect_vdso_anomalies(reported_shape(), 0, true);
        expect_clean(signals, "arm32 signal page");
    }

    void test_other_abis_keep_the_count_anomaly() {
        const char *abis[] = {"arm64", "x86", "x86_64"};
        for (const char *abi: abis) {
            const VdsoSignals signals = detect_vdso_anomalies(reported_shape(), 0, false);
            expect_count_anomaly(signals, std::string(abi) + " signal page");
        }
    }

    void test_matching_vdso_stays_clean_with_and_without_signal_page() {
        const std::uintptr_t base = 0x7a000000U;
        expect_clean(
                detect_vdso_anomalies({vdso_page(base, false)}, base, true),
                "arm32 vdso"
        );
        expect_clean(
                detect_vdso_anomalies(
                        {vdso_page(base, false), signal_page(0x70000000U, 0x1000U, false)},
                        base,
                        true
                ),
                "arm32 vdso plus signal page"
        );
    }

    void test_writable_vdso_stays_high() {
        const std::uintptr_t base = 0x7a000000U;
        const VdsoSignals signals = detect_vdso_anomalies(
                {vdso_page(base, true), signal_page(0x70000000U, 0x1000U, false)},
                base,
                true
        );
        if (!signals.remapped || signals.unusual_base || signals.findings.size() != 1U) {
            fail("writable vdso flags");
        }
        if (!has_finding(signals, FindingSeverity::kHigh, "Writable [vdso] mapping")) {
            fail("writable vdso finding");
        }
    }

    void test_mismatched_nonzero_auxv_stays_medium() {
        const std::uintptr_t base = 0x7a000000U;
        const VdsoSignals signals = detect_vdso_anomalies(
                {vdso_page(base, false), signal_page(0x70000000U, 0x1000U, false)},
                base + 0x1000U,
                true
        );
        if (signals.remapped || !signals.unusual_base || signals.findings.size() != 1U) {
            fail("mismatched auxv flags");
        }
        if (!has_finding(signals, FindingSeverity::kMedium, "vDSO base mismatch")) {
            fail("mismatched auxv finding");
        }
    }

    void test_zero_auxv_with_a_vdso_stays_clean() {
        const std::vector<MapEntry> maps = {vdso_page(0x7a000000U, false)};
        expect_clean(detect_vdso_anomalies(maps, 0, true), "arm32 vdso with zero auxv");
        expect_clean(detect_vdso_anomalies(maps, 0, false), "non-arm32 vdso with zero auxv");
    }

    void test_incomplete_shapes_keep_the_count_anomaly() {
        expect_count_anomaly(detect_vdso_anomalies({}, 0, true), "zero auxv alone");
        expect_count_anomaly(
                detect_vdso_anomalies(
                        {mapping(0x1000U, 0x2000U, true, false, true, true, "/system/bin/app_process")},
                        0,
                        true
                ),
                "missing both mappings"
        );
        expect_count_anomaly(
                detect_vdso_anomalies(
                        {
                                vdso_page(0x7a000000U, false),
                                vdso_page(0x7b000000U, false),
                                signal_page(0x70000000U, 0x1000U, false),
                        },
                        0,
                        true
                ),
                "duplicate vdso"
        );
        expect_count_anomaly(
                detect_vdso_anomalies(
                        {
                                signal_page(0x70000000U, 0x1000U, false),
                                signal_page(0x71000000U, 0x1000U, false),
                        },
                        0,
                        true
                ),
                "duplicate signal pages"
        );
        expect_count_anomaly(
                detect_vdso_anomalies({signal_page(0x70000000U, 0x1000U, true)}, 0, true),
                "writable signal page"
        );
        expect_count_anomaly(
                detect_vdso_anomalies(
                        {mapping(0x70000000U, 0x70001000U, true, false, false, true, "[sigpage]")},
                        0,
                        true
                ),
                "non-executable signal page"
        );
        expect_count_anomaly(
                detect_vdso_anomalies(
                        {mapping(0x70000000U, 0x70001000U, false, false, true, true, "[sigpage]")},
                        0,
                        true
                ),
                "non-readable signal page"
        );
        expect_count_anomaly(
                detect_vdso_anomalies(
                        {mapping(0x70000000U, 0x70001000U, true, false, true, false, "[sigpage]")},
                        0,
                        true
                ),
                "shared signal page"
        );
        expect_count_anomaly(
                detect_vdso_anomalies(
                        {mapping(0xffff0000U, 0xffff1000U, true, false, true, true, "[vectors]")},
                        0,
                        true
                ),
                "vectors page"
        );
    }

    void test_invalid_signal_page_ranges_keep_the_count_anomaly() {
        const MapEntry ranges[] = {
                mapping(0x70001000U, 0x70001000U, true, false, true, true, "[sigpage]"),
                mapping(0x70002000U, 0x70001000U, true, false, true, true, "[sigpage]"),
                signal_page(0x70000000U, 0x2000U, false),
                mapping(0x70000010U, 0x70001010U, true, false, true, true, "[sigpage]"),
        };
        for (const MapEntry &entry: ranges) {
            expect_count_anomaly(detect_vdso_anomalies({entry}, 0, true), "invalid signal page range");
        }
        expect_clean(
                detect_vdso_anomalies({signal_page(0x70000000U, 0x4000U, false)}, 0, true),
                "16k signal page"
        );
        expect_clean(
                detect_vdso_anomalies({signal_page(0x70000000U, 0x10000U, false)}, 0, true),
                "64k signal page"
        );
    }

    void test_nonzero_auxv_does_not_compare_the_signal_page() {
        const std::uintptr_t page = 0x70000000U;
        const std::vector<MapEntry> maps = {signal_page(page, 0x1000U, false)};
        expect_count_anomaly(
                detect_vdso_anomalies(maps, page, true),
                "auxv equal to signal page"
        );
        expect_count_anomaly(
                detect_vdso_anomalies(maps, page + 0x1000U, true),
                "nonzero auxv with signal page"
        );
    }

}  // namespace

int main() {
    test_arm32_signal_page_without_vdso_is_clean();
    test_other_abis_keep_the_count_anomaly();
    test_matching_vdso_stays_clean_with_and_without_signal_page();
    test_writable_vdso_stays_high();
    test_mismatched_nonzero_auxv_stays_medium();
    test_zero_auxv_with_a_vdso_stays_clean();
    test_incomplete_shapes_keep_the_count_anomaly();
    test_invalid_signal_page_ranges_keep_the_count_anomaly();
    test_nonzero_auxv_does_not_compare_the_signal_page();
    if (g_failures != 0) {
        std::fprintf(stderr, "%d failure(s)\n", g_failures);
        return 1;
    }
    std::printf("vdso detector tests passed\n");
    return 0;
}

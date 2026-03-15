/*
 * io.h — Test case splitting and output comparison.
 *
 * split() loads the full input and expected-output files and returns them as
 * one combined testcase. This matches Codeforces-style batches where the
 * program itself reads the testcase count from stdin.
 *
 * compare() does a normalized comparison of actual vs expected output,
 * trimming trailing whitespace before comparing. Returns AC or WA; on WA,
 * sets diff_snippet to a short description of the first mismatch.
 */
#pragma once

#include "common.h"
#include <expected>
#include <optional>
#include <string>
#include <vector>

/* Load input and expected-output files as either one combined testcase or
 * multiple testcase slices using byte offsets. */
std::expected<std::vector<TestCase>, int>
split(const std::string& input_path,
      const std::string& output_path,
      const std::optional<std::vector<size_t>>& input_offsets = std::nullopt,
      const std::optional<std::vector<size_t>>& output_offsets = std::nullopt);

/* Compare actual stdout against expected output.
 * Trailing whitespace/newlines are stripped from both sides before comparing.
 * For combined batch runs, this tries to infer the failing internal testcase
 * from the input/expected-output structure and reports it in diff_snippet. */
VerdictType compare(std::string_view actual,
                    std::string_view input,
                    std::string_view expected,
                    std::string&     diff_snippet);

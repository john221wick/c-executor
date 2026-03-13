/*
 * io.h — Test case splitting and output comparison.
 *
 * split() mmap's the input and expected-output files and slices them into
 * string_views using caller-provided byte offset vectors. Zero-copy: the
 * returned TestCase views point directly into mmap'd pages. The mappings are
 * kept alive in static storage inside io.cpp for the duration of the process.
 *
 * compare() does a normalized comparison of actual vs expected output,
 * trimming trailing whitespace before comparing. Returns AC or WA; on WA,
 * sets diff_snippet to a short description of the first mismatch.
 */
#pragma once

#include "common.h"
#include <expected>
#include <string>
#include <vector>

/* Split mmap'd files into TestCase views.
 *
 * input_offsets[i]  = byte offset in input_path  where test case i begins.
 * output_offsets[i] = byte offset in output_path where test case i begins.
 * The last slice in each file extends from offsets.back() to EOF.
 *
 * Returns EINVAL if the vectors are empty or have different sizes. */
std::expected<std::vector<TestCase>, int>
split(const std::string&         input_path,
      const std::string&         output_path,
      const std::vector<size_t>& input_offsets,
      const std::vector<size_t>& output_offsets);

/* Compare actual stdout against expected output.
 * Trailing whitespace/newlines are stripped from both sides before comparing.
 * diff_snippet is populated on WA with context around the first mismatch. */
VerdictType compare(std::string_view actual,
                    std::string_view expected,
                    std::string&     diff_snippet);

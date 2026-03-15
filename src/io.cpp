/*
 * io.cpp — buffered test case splitting and output comparison.
 *
 * Loaded file buffers are stored in a process-global list so the string_views
 * inside TestCase remain valid for the lifetime of the process. This is safe
 * because the executor processes one batch of test cases and then exits.
 *
 * compare() strips trailing whitespace from both sides before comparing,
 * which avoids WA verdicts caused by trailing newlines.
 */
#include "io.h"
#include "logger.h"
#include <cerrno>
#include <charconv>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <optional>
#include <mutex>
#include <memory>

/* ── Buffer lifetime management ────────────────────────────────────────── */

/* Global list keeps file contents alive as long as the process lives. */
static std::vector<std::shared_ptr<std::string>> g_buffers;
static std::mutex                                g_buffers_mu;

static std::expected<std::string_view, int> load_file(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return std::unexpected(errno);

    struct stat st{};
    if (fstat(fd, &st) < 0) { close(fd); return std::unexpected(errno); }

    if (st.st_size == 0) {
        close(fd);
        /* Return an empty view; store nothing. */
        return std::string_view{};
    }

    auto buffer = std::make_shared<std::string>();
    buffer->resize(static_cast<size_t>(st.st_size));
    ssize_t n = read(fd, buffer->data(), buffer->size());
    close(fd);

    if (n < 0) return std::unexpected(errno);
    if (static_cast<size_t>(n) != buffer->size()) return std::unexpected(EIO);

    {
        std::lock_guard lock(g_buffers_mu);
        g_buffers.push_back(buffer);
    }

    return std::string_view{buffer->data(), buffer->size()};
}

/* ── split() ────────────────────────────────────────────────────────────── */

std::expected<std::vector<TestCase>, int>
split(const std::string& input_path,
      const std::string& output_path)
{
    auto in_view  = load_file(input_path);
    if (!in_view)  return std::unexpected(in_view.error());

    auto out_view = load_file(output_path);
    if (!out_view) return std::unexpected(out_view.error());

    return std::vector<TestCase>{TestCase{
        .id              = 0,
        .input           = *in_view,
        .expected_output = *out_view,
    }};
}

/* ── compare() ──────────────────────────────────────────────────────────── */

/* Strip trailing whitespace (' ', '\t', '\r', '\n'). */
static std::string_view rtrim(std::string_view s) {
    while (!s.empty() && (s.back() == ' '  || s.back() == '\t' ||
                           s.back() == '\r' || s.back() == '\n'))
        s.remove_suffix(1);
    return s;
}

static std::string_view ltrim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' ||
                           s.front() == '\r' || s.front() == '\n'))
        s.remove_prefix(1);
    return s;
}

static std::string_view trim(std::string_view s) {
    return ltrim(rtrim(s));
}

static std::vector<std::string_view> split_lines(std::string_view s) {
    std::vector<std::string_view> lines;
    size_t start = 0;
    while (start < s.size()) {
        size_t end = s.find('\n', start);
        if (end == std::string_view::npos) {
            lines.push_back(s.substr(start));
            return lines;
        }
        lines.push_back(s.substr(start, end - start));
        start = end + 1;
    }
    return lines;
}

static std::optional<size_t> parse_batch_case_count(std::string_view input) {
    size_t end = input.find('\n');
    std::string_view first_line =
        (end == std::string_view::npos) ? input : input.substr(0, end);
    first_line = trim(first_line);
    if (first_line.empty()) return std::nullopt;

    size_t value = 0;
    auto [ptr, ec] = std::from_chars(
        first_line.data(),
        first_line.data() + first_line.size(),
        value
    );
    if (ec != std::errc{} || ptr != first_line.data() + first_line.size() || value < 2)
        return std::nullopt;

    return value;
}

struct CaseLocation {
    size_t case_index   = 0; /* 1-based */
    size_t line_in_case = 0; /* 1-based */
};

static std::optional<CaseLocation> infer_equal_line_case(
        std::string_view input,
        const std::vector<std::string_view>& expected_lines,
        size_t mismatch_line) {
    auto batch_count = parse_batch_case_count(input);
    if (!batch_count || expected_lines.empty()) return std::nullopt;
    if (expected_lines.size() % *batch_count != 0) return std::nullopt;

    const size_t lines_per_case = expected_lines.size() / *batch_count;
    if (lines_per_case == 0) return std::nullopt;

    const size_t case_index =
        std::min(*batch_count, ((mismatch_line - 1) / lines_per_case) + 1);
    const size_t line_in_case = ((mismatch_line - 1) % lines_per_case) + 1;
    return CaseLocation{case_index, line_in_case};
}

static std::optional<CaseLocation> infer_blank_separated_case(
        std::string_view input,
        const std::vector<std::string_view>& expected_lines,
        size_t mismatch_line) {
    auto batch_count = parse_batch_case_count(input);
    if (!batch_count) return std::nullopt;

    struct Block {
        size_t start_line = 0;
        size_t end_line   = 0;
    };

    std::vector<Block> blocks;
    size_t line_no = 1;
    bool in_block = false;
    Block current{};

    for (const auto& line : expected_lines) {
        if (trim(line).empty()) {
            if (in_block) {
                blocks.push_back(current);
                in_block = false;
            }
        } else {
            if (!in_block) {
                current = Block{line_no, line_no};
                in_block = true;
            } else {
                current.end_line = line_no;
            }
        }
        ++line_no;
    }

    if (in_block) blocks.push_back(current);
    if (blocks.size() != *batch_count) return std::nullopt;

    for (size_t i = 0; i < blocks.size(); ++i) {
        const auto& block = blocks[i];
        if (mismatch_line >= block.start_line && mismatch_line <= block.end_line) {
            return CaseLocation{i + 1, mismatch_line - block.start_line + 1};
        }
    }

    if (mismatch_line < blocks.front().start_line) {
        return CaseLocation{1, 1};
    }
    return CaseLocation{blocks.size(), blocks.back().end_line - blocks.back().start_line + 1};
}

static std::string format_line_value(const std::vector<std::string_view>& lines,
                                      size_t index) {
    if (index >= lines.size()) return "<missing>";
    return std::string(lines[index]);
}

VerdictType compare(std::string_view actual,
                    std::string_view input,
                    std::string_view expected,
                    std::string&     diff_snippet)
{
    std::string_view a = rtrim(actual);
    std::string_view e = rtrim(expected);

    if (a == e) return VerdictType::AC;

    auto actual_lines   = split_lines(a);
    auto expected_lines = split_lines(e);

    size_t mismatch_index = 0;
    const size_t common = std::min(actual_lines.size(), expected_lines.size());
    while (mismatch_index < common &&
            actual_lines[mismatch_index] == expected_lines[mismatch_index]) {
        ++mismatch_index;
    }

    const size_t mismatch_line = mismatch_index + 1;
    const std::string got      = format_line_value(actual_lines, mismatch_index);
    const std::string expected_value = format_line_value(expected_lines, mismatch_index);

    auto location = infer_blank_separated_case(input, expected_lines, mismatch_line);
    if (!location)
        location = infer_equal_line_case(input, expected_lines, mismatch_line);

    if (location) {
        diff_snippet = "case " + std::to_string(location->case_index) +
                       ", line " + std::to_string(location->line_in_case) + ": ";
    } else {
        diff_snippet = "line " + std::to_string(mismatch_line) + ": ";
    }
    diff_snippet += "got \"";
    diff_snippet.append(got);
    diff_snippet += "\" expected \"";
    diff_snippet.append(expected_value);
    diff_snippet += "\"";

    return VerdictType::WA;
}

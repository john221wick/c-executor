/*
 * io.cpp — mmap-based test case splitting and output comparison.
 *
 * The mmap'd regions are stored in a process-global list so the string_views
 * inside TestCase remain valid for the lifetime of the process. This is safe
 * because the executor processes one batch of test cases and then exits.
 *
 * compare() strips trailing whitespace from both sides before comparing,
 * which avoids WA verdicts caused by trailing newlines.
 */
#include "io.h"
#include "logger.h"
#include <cerrno>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mutex>
#include <memory>

/* ── Mmap lifetime management ──────────────────────────────────────────── */

struct MmapRegion {
    void*  addr = MAP_FAILED;
    size_t len  = 0;
    ~MmapRegion() {
        if (addr != MAP_FAILED) munmap(addr, len);
    }
};

/* Global list keeps mappings alive as long as the process lives. */
static std::vector<std::shared_ptr<MmapRegion>> g_mappings;
static std::mutex                                g_mappings_mu;

static std::expected<std::string_view, int> mmap_file(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return std::unexpected(errno);

    struct stat st{};
    if (fstat(fd, &st) < 0) { close(fd); return std::unexpected(errno); }

    if (st.st_size == 0) {
        close(fd);
        /* Return an empty view; store nothing. */
        return std::string_view{};
    }

    void* addr = mmap(nullptr, static_cast<size_t>(st.st_size),
                      PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (addr == MAP_FAILED) return std::unexpected(errno);

    auto region = std::make_shared<MmapRegion>(MmapRegion{addr, static_cast<size_t>(st.st_size)});
    {
        std::lock_guard lock(g_mappings_mu);
        g_mappings.push_back(region);
    }

    return std::string_view{static_cast<const char*>(addr),
                             static_cast<size_t>(st.st_size)};
}

/* ── split() ────────────────────────────────────────────────────────────── */

std::expected<std::vector<TestCase>, int>
split(const std::string&         input_path,
      const std::string&         output_path,
      const std::vector<size_t>& input_offsets,
      const std::vector<size_t>& output_offsets)
{
    if (input_offsets.empty() || input_offsets.size() != output_offsets.size())
        return std::unexpected(EINVAL);

    auto in_view  = mmap_file(input_path);
    if (!in_view)  return std::unexpected(in_view.error());

    auto out_view = mmap_file(output_path);
    if (!out_view) return std::unexpected(out_view.error());

    const size_t n = input_offsets.size();
    std::vector<TestCase> cases;
    cases.reserve(n);

    for (size_t i = 0; i < n; ++i) {
        size_t in_start  = input_offsets[i];
        size_t in_end    = (i + 1 < n) ? input_offsets[i + 1] : in_view->size();
        size_t out_start = output_offsets[i];
        size_t out_end   = (i + 1 < n) ? output_offsets[i + 1] : out_view->size();

        if (in_start > in_view->size() || out_start > out_view->size())
            return std::unexpected(ERANGE);

        cases.push_back(TestCase{
            .id              = static_cast<uint32_t>(i),
            .input           = in_view->substr(in_start, in_end - in_start),
            .expected_output = out_view->substr(out_start, out_end - out_start),
        });
    }

    return cases;
}

/* ── compare() ──────────────────────────────────────────────────────────── */

/* Strip trailing whitespace (' ', '\t', '\r', '\n'). */
static std::string_view rtrim(std::string_view s) {
    while (!s.empty() && (s.back() == ' '  || s.back() == '\t' ||
                           s.back() == '\r' || s.back() == '\n'))
        s.remove_suffix(1);
    return s;
}

VerdictType compare(std::string_view actual,
                    std::string_view expected,
                    std::string&     diff_snippet)
{
    std::string_view a = rtrim(actual);
    std::string_view e = rtrim(expected);

    if (a == e) return VerdictType::AC;

    /* Build a short diff snippet: show line number and content of first mismatch. */
    size_t line = 1;
    size_t i    = 0;
    while (i < a.size() && i < e.size()) {
        if (a[i] == '\n') ++line;
        if (a[i] != e[i]) break;
        ++i;
    }

    /* Extract context: up to 80 chars around the mismatch on each side. */
    size_t ctx_start = (i > 40) ? i - 40 : 0;
    auto   a_ctx     = a.substr(ctx_start, std::min<size_t>(80, a.size() - ctx_start));
    auto   e_ctx     = e.substr(ctx_start, std::min<size_t>(80, e.size() - ctx_start));

    diff_snippet  = "line " + std::to_string(line) + ": ";
    diff_snippet += "got \"";
    diff_snippet.append(a_ctx);
    diff_snippet += "\" expected \"";
    diff_snippet.append(e_ctx);
    diff_snippet += "\"";

    return VerdictType::WA;
}

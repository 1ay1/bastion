#include "bastion/ledger.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

namespace bastion {

namespace {

std::string parent_of(const std::string& p) {
    auto pos = p.rfind('/');
    if (pos == std::string::npos || pos == 0) return "/";
    return p.substr(0, pos);
}

bool is_forbidden_widening(const std::string& dir, const SynthesisOptions& o) {
    return std::find(o.never_widen_to.begin(), o.never_widen_to.end(), dir) !=
           o.never_widen_to.end();
}

Right right_for_op(std::string_view op) {
    if (op == "fs.read")    return Right::FsRead;
    if (op == "fs.write")   return Right::FsWrite;
    if (op == "fs.exec")    return Right::FsExec;
    if (op == "net.egress") return Right::NetEgress;
    if (op == "net.bind")   return Right::NetBind;
    return Right::None;
}

// The single op name that best describes a right set.
//
// NOTE the lossiness, which is deliberate but load-bearing: a rule carrying
// Read|Write collapses to "fs.write". A policy FILE has one op per [[allow]]
// block, so synthesize() emits a separate block for the read -- see to_toml().
// Emitting only the write produced a directory the workload could not create
// files in: Landlock needs read on a directory to resolve a path inside it, so
// `ld` failed with "cannot open output file: Permission denied" under a policy
// that plainly said fs.write on that very directory.
std::string_view op_for_right(Right r) {
    if (any(r & Right::FsWrite))   return "fs.write";
    if (any(r & Right::FsExec))    return "fs.exec";
    if (any(r & Right::FsRead))    return "fs.read";
    if (any(r & Right::NetEgress)) return "net.egress";
    return "unknown";
}

std::string rights_to_cpp(Right r) {
    std::string s;
    auto add = [&](const char* n) {
        if (!s.empty()) s += " | ";
        s += "Right::";
        s += n;
    };
    if (any(r & Right::FsRead))    add("FsRead");
    if (any(r & Right::FsWrite))   add("FsWrite");
    if (any(r & Right::FsExec))    add("FsExec");
    if (any(r & Right::NetEgress)) add("NetEgress");
    if (any(r & Right::NetBind))   add("NetBind");
    return s.empty() ? "Right::None" : s;
}

// Paths that the backend's ergonomic floor already covers. Emitting rules for
// these bloats a synthesized policy with noise (dyld, locale tables, /bin/sh
// itself) and hides the handful of grants that actually matter.
//
// Observation sees EVERYTHING a process touches, including all the machinery
// the base profile grants anyway -- 48 raw records for a shell that read one
// file. Filtering here is what makes the output reviewable.
bool covered_by_floor(std::string_view op, std::string_view path) {
    if (op == "fs.stat") return true;  // traversal metadata, always granted

    static constexpr std::string_view kFloorRead[] = {
        "/usr/lib", "/usr/share", "/System", "/Library/Preferences",
        "/private/var/db/dyld", "/usr/bin", "/bin", "/usr/sbin", "/sbin",
        "/private/var/select", "/Library/Developer", "/Applications/Xcode.app",
        "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/tty",
        "/dev/dtracehelper", "/dev/fd", "/dev/stdout", "/dev/stderr",
        "/dev/stdin", "/dev/ptmx", "/dev/console",
    };
    for (auto f : kFloorRead) {
        if (path == f) return true;
        if (path.size() > f.size() && path.starts_with(f) && path[f.size()] == '/') {
            return true;
        }
    }
    // /dev/ttysNNN and similar.
    if (path.starts_with("/dev/ttys")) return true;
    return false;
}

}  // namespace

void Ledger::record(const AuditRecord& rec) { records_.push_back(rec); }

std::string Ledger::flush() {
    std::error_code ec;
    auto dir = std::filesystem::path{path_}.parent_path();
    if (!dir.empty()) std::filesystem::create_directories(dir, ec);

    std::ofstream f(path_, std::ios::app);
    if (!f) return "cannot open ledger for writing: " + path_;
    for (const auto& r : records_) f << r.to_json() << "\n";
    if (!f) return "write failed: " + path_;
    return {};
}

std::optional<Ledger> Ledger::load(const std::string& path, std::string& error) {
    std::ifstream f(path);
    if (!f) {
        error = "cannot open ledger: " + path;
        return std::nullopt;
    }
    Ledger led{path};
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;

        // Minimal field extraction; the ledger format is our own JSONL.
        auto field = [&](std::string_view key) -> std::string {
            std::string pat = "\"" + std::string{key} + "\":\"";
            auto s = line.find(pat);
            if (s == std::string::npos) return {};
            s += pat.size();
            std::string out;
            for (std::size_t i = s; i < line.size(); ++i) {
                if (line[i] == '\\' && i + 1 < line.size()) {
                    char n = line[++i];
                    out += (n == 'n') ? '\n' : (n == 't') ? '\t' : n;
                    continue;
                }
                if (line[i] == '"') break;
                out += line[i];
            }
            return out;
        };

        AuditRecord rec;
        rec.op = field("op");
        rec.target = field("target");
        rec.rule = field("rule");
        rec.provenance = field("provenance");
        const std::string v = field("verdict");
        rec.verdict = (v == "allow")      ? Verdict::Allow
                      : (v == "would_deny") ? Verdict::WouldDeny
                                            : Verdict::Deny;
        if (rec.op.empty() || rec.target.empty()) continue;  // skip junk
        led.record(rec);
    }
    return led;
}

Synthesis synthesize(const Ledger& ledger, const SynthesisOptions& opts) {
    Synthesis syn;

    // right -> set of concrete targets observed needing it
    std::map<std::uint32_t, std::set<std::string>> need;

    for (const auto& r : ledger.records()) {
        ++syn.observations;
        if (r.verdict == Verdict::Deny) {
            ++syn.denials_seen;
            // A hard denial the program survived is NOT evidence of a need:
            // synthesizing a grant for it would silently widen the policy to
            // cover attacks the sandbox successfully stopped.
            continue;
        }
        Right rr = right_for_op(r.op);
        if (rr == Right::None) continue;
        if (r.target.empty() || r.target == "*") continue;

        // The root directory is granted by the base profile (dyld reads it).
        // A synthesized `fs.read /` would hand over the ENTIRE filesystem --
        // the exact opposite of least privilege. Observation legitimately sees
        // this access, so it must be filtered here rather than trusted.
        if (r.target == "/") {
            ++syn.floor_filtered;
            continue;
        }
        if (covered_by_floor(r.op, r.target)) {
            ++syn.floor_filtered;
            continue;
        }
        need[std::to_underlying(rr)].insert(r.target);
    }

    for (auto& [bits, targets] : need) {
        const Right r = static_cast<Right>(bits);

        // Coalesce siblings into a parent directory once enough distinct
        // children are observed, so the output stays readable.
        std::map<std::string, std::size_t> parent_count;
        const bool is_fs = any(r & (Right::FsRead | Right::FsWrite | Right::FsExec));
        if (is_fs) {
            for (const auto& t : targets) parent_count[parent_of(t)]++;
        }

        // A WRITE is coalesced to its directory even from a single observation.
        //
        // MEASURED: observing `cc m.c -o m` yields one write (m) and two reads
        // in the workspace -- all below the threshold, so the policy granted
        // three individual FILE paths. Re-running it then failed, because a
        // build's outputs are NEW files every time: the compiler's temp object
        // (/tmp/ccSTSQAG.o) and any renamed output were never covered. The
        // synthesized policy only worked for the exact run it was derived
        // from, which defeats the entire on-ramp.
        //
        // Creating a file requires authority over the DIRECTORY, so a write
        // grant on a path is evidence the directory is a work area. Reads keep
        // the higher threshold: reading one file is not evidence you need its
        // whole directory, and over-granting reads is how a sandbox quietly
        // stops confining anything.
        const bool writes = any(r & Right::FsWrite);
        const std::size_t threshold =
            writes ? 1 : opts.coalesce_threshold;

        std::set<std::string> emitted;
        std::set<std::string> emitted_dirs;  // the coalesced ones only
        std::set<std::string> covered;

        for (const auto& [dir, count] : parent_count) {
            if (count < threshold) continue;
            if (is_forbidden_widening(dir, opts)) {
                syn.notes.push_back(
                    "declined to coalesce " + std::to_string(count) +
                    " paths into '" + dir +
                    "' (too broad); emitting individual rules instead");
                continue;
            }
            emitted.insert(dir);
            emitted_dirs.insert(dir);
            for (const auto& t : targets) {
                if (parent_of(t) == dir) covered.insert(t);
            }
        }

        for (const auto& t : targets) {
            if (!covered.contains(t)) emitted.insert(t);
        }

        for (const auto& scope : emitted) {
            Right granted = r;
            // A directory you may WRITE into must also be READable: Landlock
            // needs read on a directory to resolve a path inside it, so a
            // write-only grant means `ld` cannot create its output there --
            // "cannot open output file: Permission denied" under a policy that
            // plainly says fs.write on that directory. Only applied to the
            // coalesced DIRECTORY rules, not to individual files, so this
            // widens nothing the write grant did not already imply.
            if (writes && emitted_dirs.contains(scope)) {
                // operator| is consteval by design (rights are meant to be
                // composed at compile time), so combine through the underlying
                // bits rather than weakening that guarantee for every caller.
                granted = static_cast<Right>(std::to_underlying(granted) |
                                             std::to_underlying(Right::FsRead));
            }
            syn.rules.push_back(
                Rule{granted, scope, "synthesized from observed use"});
        }
    }

    std::sort(syn.rules.begin(), syn.rules.end(), [](const Rule& a, const Rule& b) {
        if (a.scope != b.scope) return a.scope < b.scope;
        return std::to_underlying(a.right) < std::to_underlying(b.right);
    });

    if (syn.denials_seen > 0) {
        syn.notes.push_back(
            std::to_string(syn.denials_seen) +
            " denied operation(s) were NOT turned into grants. Review them: "
            "each is either a bug in your policy or an attack it stopped.");
    }
    return syn;
}

std::string Synthesis::to_toml() const {
    std::ostringstream o;
    o << "# Synthesized by `bastion synthesize` from " << observations
      << " observed operation(s).\n";
    if (floor_filtered > 0) {
        o << "# " << floor_filtered
          << " access(es) omitted: already covered by the ergonomic floor\n"
          << "# (dyld, locale data, /bin, /dev/null, traversal metadata, ...).\n";
    }
    o << "# This is the MINIMAL policy that would have allowed everything the\n"
      << "# program actually did. Review before committing.\n\n";

    if (!rules.empty()) o << "tier = \"T2\"\n\n";

    for (const auto& note : notes) o << "# NOTE: " << note << "\n";
    if (!notes.empty()) o << "\n";

    for (const auto& r : rules) {
        o << "[[allow]]\n"
          << "op    = \"" << op_for_right(r.right) << "\"\n"
          << "path  = \"" << r.scope << "\"\n"
          << "why   = \"" << r.provenance << "\"\n\n";

        // A policy file carries ONE op per block, but a right set can hold
        // several. op_for_right() reports the strongest, so a Read|Write grant
        // would silently lose its read -- and a write-only directory is one
        // Landlock cannot create files in (`ld: cannot open output file`).
        // Emit the companion block rather than dropping the right.
        if (any(r.right & Right::FsWrite) && any(r.right & Right::FsRead)) {
            o << "[[allow]]\n"
              << "op    = \"fs.read\"\n"
              << "path  = \"" << r.scope << "\"\n"
              << "why   = \"" << r.provenance
              << " (read is required to write here)\"\n\n";
        }
    }
    if (rules.empty()) {
        // NEVER claim a workload needs nothing just because we recorded
        // nothing. The original version of this code printed "No grants
        // needed" for a program that had demonstrably read /etc/hosts and
        // written /tmp -- a confident, wrong answer, which is worse than no
        // answer. If there is no filesystem/network evidence, say so and point
        // at the command that produces it.
        o << "# !! NO ACCESS EVIDENCE IN THE LEDGER.\n"
          << "#\n"
          << "# This is NOT the same as \"the program needs no permissions\".\n";
        if (observations > 0) {
            o << "# The ledger holds " << observations
              << " record(s), but none of them are file or network\n"
              << "# accesses -- `bastion run` records that a process was\n"
              << "# spawned, not what it touched.\n";
        }
        o << "#\n"
          << "# To collect real evidence, run the workload under observation:\n"
          << "#\n"
          << "#     bastion observe -- <your command>\n"
          << "#     bastion synthesize\n"
          << "#\n"
          << "# Refusing to emit a policy that would look tight but was\n"
          << "# derived from nothing.\n";
        return o.str();
    }
    return o.str();
}

std::string Synthesis::to_cpp() const {
    std::ostringstream o;
    o << "// Synthesized by `bastion synthesize` from " << observations
      << " observed operation(s).\n"
      << "auto policy = bastion::Policy{bastion::Tier::Kernel}\n";
    for (const auto& r : rules) {
        o << "    .allow(" << rights_to_cpp(r.right) << ", \"" << r.scope
          << "\", \"observed\")\n";
    }
    o << "    .seal();\n";
    return o.str();
}

}  // namespace bastion

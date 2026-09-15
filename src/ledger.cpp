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

        std::set<std::string> emitted;
        std::set<std::string> covered;

        for (const auto& [dir, count] : parent_count) {
            if (count < opts.coalesce_threshold) continue;
            if (is_forbidden_widening(dir, opts)) {
                syn.notes.push_back(
                    "declined to coalesce " + std::to_string(count) +
                    " paths into '" + dir +
                    "' (too broad); emitting individual rules instead");
                continue;
            }
            emitted.insert(dir);
            for (const auto& t : targets) {
                if (parent_of(t) == dir) covered.insert(t);
            }
        }

        for (const auto& t : targets) {
            if (!covered.contains(t)) emitted.insert(t);
        }

        for (const auto& scope : emitted) {
            syn.rules.push_back(Rule{r, scope, "synthesized from observed use"});
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
      << " observed operation(s).\n"
      << "# This is the MINIMAL policy that would have allowed everything the\n"
      << "# program actually did. Review before committing.\n\n"
      << "tier = \"T2\"\n\n";

    for (const auto& note : notes) o << "# NOTE: " << note << "\n";
    if (!notes.empty()) o << "\n";

    for (const auto& r : rules) {
        o << "[[allow]]\n"
          << "op    = \"" << op_for_right(r.right) << "\"\n"
          << "path  = \"" << r.scope << "\"\n"
          << "why   = \"" << r.provenance << "\"\n\n";
    }
    if (rules.empty()) {
        o << "# No grants needed: the program touched nothing outside the\n"
          << "# ergonomic floor. You can run this at T2 with no rules at all.\n";
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

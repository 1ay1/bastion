#include "bastion/policy_file.hpp"

#include <fstream>
#include <sstream>

namespace bastion {

namespace {

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) {
        s.remove_suffix(1);
    }
    return s;
}

// Unquote a TOML basic string, honouring the escapes to_toml() can emit.
// Returns false if the value is not a quoted string.
bool unquote(std::string_view in, std::string& out) {
    in = trim(in);
    if (in.size() < 2 || in.front() != '"' || in.back() != '"') return false;
    in.remove_prefix(1);
    in.remove_suffix(1);
    out.clear();
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '\\' && i + 1 < in.size()) {
            switch (in[++i]) {
                case 'n': out += '\n'; break;
                case 't': out += '\t'; break;
                case 'r': out += '\r'; break;
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                default: out += in[i]; break;
            }
            continue;
        }
        out += in[i];
    }
    return true;
}

Tier parse_tier_name(std::string_view s, bool& ok) {
    ok = true;
    if (s == "T0" || s == "t0" || s == "observe")    return Tier::Observe;
    if (s == "T1" || s == "t1" || s == "advisory")   return Tier::Advisory;
    if (s == "T2" || s == "t2" || s == "kernel")     return Tier::Kernel;
    if (s == "T3" || s == "t3" || s == "isolate")    return Tier::Isolate;
    if (s == "T4" || s == "t4" || s == "virtualize") return Tier::Virtualize;
    ok = false;
    return Tier::Kernel;
}

Right right_for_op_name(std::string_view op) {
    if (op == "fs.read")    return Right::FsRead;
    if (op == "fs.write")   return Right::FsWrite;
    if (op == "fs.exec")    return Right::FsExec;
    if (op == "net.egress") return Right::NetEgress;
    if (op == "net.bind")   return Right::NetBind;
    return Right::None;
}

// One [[allow]] block under construction.
struct Pending {
    bool active = false;
    std::string op;
    std::string path;
    std::string why;
    int line = 0;
};

}  // namespace

Result<PolicyFile> parse_policy(std::string_view text) {
    PolicyFile pf;
    Pending cur;

    // A parse failure now RETURNS instead of stashing a flag, so there is no
    // way to reach the partially-built pf afterwards.
    const auto at = [](std::string msg, int line) {
        return Error{ParseError{std::move(msg), line}.describe()};
    };

    auto flush = [&](std::string& err, int& errline) -> bool {
        if (!cur.active) return true;
        if (cur.op.empty()) {
            err = "[[allow]] block is missing `op`";
            errline = cur.line;
            return false;
        }
        if (cur.path.empty()) {
            err = "[[allow]] block for op '" + cur.op + "' is missing `path`";
            errline = cur.line;
            return false;
        }
        const Right r = right_for_op_name(cur.op);
        if (r == Right::None) {
            // Fail closed: an op we do not understand might be one we should
            // have restricted. Silently dropping it would quietly widen or
            // narrow the policy without telling anyone.
            err = "unknown op '" + cur.op +
                  "' (expected fs.read, fs.write, fs.exec, net.egress, "
                  "net.bind)";
            errline = cur.line;
            return false;
        }
        pf.rules.push_back(Rule{r, cur.path,
                                cur.why.empty() ? "from policy file" : cur.why});
        cur = Pending{};
        return true;
    };

    std::istringstream in{std::string{text}};
    std::string raw;
    int lineno = 0;
    std::string ferr;
    int fline = 0;

    while (std::getline(in, raw)) {
        ++lineno;
        std::string_view line = trim(raw);
        if (line.empty() || line.front() == '#') continue;

        if (line == "[[allow]]") {
            if (!flush(ferr, fline)) return at(ferr, fline);
            cur.active = true;
            cur.line = lineno;
            continue;
        }
        if (line.front() == '[') {
            // Any other table ends the current block; unknown tables are
            // reported rather than ignored.
            if (!flush(ferr, fline)) return at(ferr, fline);
            pf.warnings.emplace_back("ignoring unknown table " +
                                     std::string{line} + " at line " +
                                     std::to_string(lineno));
            continue;
        }

        const auto eq = line.find('=');
        if (eq == std::string_view::npos) {
            return at("expected `key = value`", lineno);
        }
        const std::string_view key = trim(line.substr(0, eq));
        const std::string_view val = trim(line.substr(eq + 1));

        std::string sval;
        if (!unquote(val, sval)) {
            return at("value for `" + std::string{key} +
                          "` must be a quoted string",
                      lineno);
        }

        if (!cur.active) {
            if (key == "tier") {
                bool ok = false;
                pf.tier = parse_tier_name(sval, ok);
                if (!ok) {
                    return at("unknown tier '" + sval + "'", lineno);
                }
            } else {
                pf.warnings.emplace_back("ignoring unknown key `" +
                                         std::string{key} + "` at line " +
                                         std::to_string(lineno));
            }
            continue;
        }

        if (key == "op")        cur.op = sval;
        else if (key == "path") cur.path = sval;
        else if (key == "why")  cur.why = sval;
        else {
            pf.warnings.emplace_back("ignoring unknown key `" +
                                     std::string{key} + "` in [[allow]] at line " +
                                     std::to_string(lineno));
        }
    }

    if (!flush(ferr, fline)) return at(ferr, fline);
    return pf;
}

Result<PolicyFile> load_policy(const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        return Error{"cannot open policy file: " + path};
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return parse_policy(ss.str());
}

Sealed to_sealed(const PolicyFile& pf) {
    Policy p{pf.tier};
    for (const auto& r : pf.rules) {
        if (any(r.right & (Right::NetEgress | Right::NetBind))) {
            p = std::move(p).allow_egress(r.scope, r.provenance);
        } else {
            p = std::move(p).allow(r.right, r.scope, r.provenance);
        }
    }
    return std::move(p).seal();
}

}  // namespace bastion

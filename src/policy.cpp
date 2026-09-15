#include "bastion/policy.hpp"

#include <sstream>

namespace bastion {

namespace {

std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\t': out += "\\t";  break;
            case '\r': out += "\\r";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[7];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

constexpr std::string_view verdict_name(Verdict v) {
    switch (v) {
        case Verdict::Allow:     return "allow";
        case Verdict::Deny:      return "deny";
        case Verdict::WouldDeny: return "would_deny";
    }
    return "unknown";
}

// Does `scope` cover `target`? Path-prefix containment on canonical paths, with
// a component boundary check so /work never matches /workspace-other.
bool covers(std::string_view scope, std::string_view target) {
    if (scope == "*") return true;
    if (scope == target) return true;
    if (target.size() > scope.size() && target.starts_with(scope)) {
        return scope.ends_with('/') || target[scope.size()] == '/';
    }
    return false;
}

Right right_for_op(std::string_view op) {
    if (op == "fs.read")     return Right::FsRead;
    if (op == "fs.write")    return Right::FsWrite;
    if (op == "fs.exec")     return Right::FsExec;
    if (op == "net.egress")  return Right::NetEgress;
    if (op == "net.bind")    return Right::NetBind;
    if (op == "proc.spawn")  return Right::ProcSpawn;
    if (op == "device.open") return Right::DeviceWrite;
    if (op == "ipc.connect") return Right::Ipc;
    return Right::None;
}

Remedy remedy_for(std::string_view op, std::string_view target) {
    std::string cap_name{op == "fs.write"   ? "FsWrite"
                         : op == "fs.read"  ? "FsRead"
                         : op == "fs.exec"  ? "FsExec"
                         : op == "net.egress" ? "NetEgress"
                                              : "Cap"};
    Remedy r;
    r.grant = cap_name + "(" + std::string{target} + ")";

    // The remedy must be a command that ACTUALLY EXISTS. This previously
    // emitted `bastion grant <op> <path>`, which was never implemented -- an
    // agent following the instruction would just get "unknown subcommand", and
    // the machine-readable denial (DESIGN.md §4.1) would be worse than silence
    // because it sends the reader somewhere that cannot help.
    if (op == "net.egress") {
        r.cmd = "bastion run -t t3 --net " + std::string{target} + " -- <cmd>";
        r.sanctioned_alternative =
            "use an allowlisted host, or re-run with --net for this one";
    } else if (op == "fs.write") {
        r.cmd = "bastion run -w " + std::string{target} + " -- <cmd>";
        r.sanctioned_alternative = "write under $WORKSPACE or $TMPDIR";
    } else if (op == "fs.read") {
        r.cmd = "bastion run -r " + std::string{target} + " -- <cmd>";
        r.sanctioned_alternative = "read under $WORKSPACE";
    } else {
        r.cmd = "bastion run -w " + std::string{target} + " -- <cmd>";
    }
    return r;
}

}  // namespace

std::string AuditRecord::to_json() const {
    std::ostringstream o;
    o << "{\"verdict\":\"" << verdict_name(verdict) << "\""
      << ",\"op\":\"" << json_escape(op) << "\""
      << ",\"target\":\"" << json_escape(target) << "\""
      << ",\"tier\":\"" << tier_name(tier) << "\""
      << ",\"rule\":\"" << json_escape(rule) << "\"";
    if (!provenance.empty()) {
        o << ",\"provenance\":\"" << json_escape(provenance) << "\"";
    }
    if (remedy) {
        o << ",\"remedy\":{\"grant\":\"" << json_escape(remedy->grant) << "\""
          << ",\"cmd\":\"" << json_escape(remedy->cmd) << "\"}";
        if (!remedy->sanctioned_alternative.empty()) {
            o << ",\"sanctioned_alternative\":\""
              << json_escape(remedy->sanctioned_alternative) << "\"";
        }
    }
    o << "}";
    return o.str();
}

AuditRecord Sealed::evaluate(std::string_view op, std::string_view target) const {
    AuditRecord rec;
    rec.op = std::string{op};
    rec.target = std::string{target};
    rec.tier = tier_;

    const Right needed = right_for_op(op);

    // Rules are stored canonicalized (Policy::allow), so the target must be
    // canonicalized too or nothing matches. Measured consequence of DESIGN.md
    // §2.1: on macOS /tmp -> /private/tmp and /etc -> /private/etc, so
    // comparing a raw target against a canonical rule silently UNDER-grants
    // and the agent thrashes. Only filesystem ops are paths.
    std::string subject{target};
    if (op.starts_with("fs.") || op == "device.open") {
        std::error_code ec;
        auto canon = std::filesystem::weakly_canonical(subject, ec);
        if (!ec) subject = canon.string();
    }

    // Unconfined short-circuits the decision but NOT the record. This is the
    // whole point: a wide-open session still produces a complete ledger, so
    // the bypass is an on-ramp to a tight policy rather than the end of
    // observability (DESIGN.md §1).
    for (const auto& r : rules_) {
        if (!subsumes(r.right, needed)) continue;
        if (!covers(r.scope, subject)) continue;
        rec.verdict = Verdict::Allow;
        rec.rule = (r.right == Right::Unconfined)
                       ? "unconfined"
                       : std::string{op} + "(" + r.scope + ")";
        rec.provenance = r.provenance;
        return rec;
    }

    // Denied. At T0/T1 we report WouldDeny: the evaluation is real, the
    // enforcement is not, and the record says so honestly rather than implying
    // a boundary that does not exist.
    rec.verdict = (tier_ <= Tier::Advisory) ? Verdict::WouldDeny : Verdict::Deny;
    rec.rule = "default-deny";
    rec.remedy = remedy_for(op, target);
    return rec;
}

std::string Sealed::explain() const {
    std::ostringstream o;
    o << "tier:      " << tier_name(tier_) << "\n"
      << "guarantee: " << tier_guarantee(tier_) << "\n";

    if (unconfined_) {
        o << "\n!! UNCONFINED GRANT ACTIVE -- no access restriction is enforced.\n"
          << "   Auditing remains fully active; every operation is still\n"
          << "   recorded and attributed. Run `bastion synthesize` to turn this\n"
          << "   session's log into a minimal least-privilege policy.\n";
        for (const auto& r : rules_) {
            if (r.right == Right::Unconfined) {
                o << "   witness: " << r.provenance << "\n";
            }
        }
    }

    o << "\nrules (" << rules_.size() << "):\n";
    for (const auto& r : rules_) {
        o << "  ";
        if (any(r.right & Right::FsRead))    o << "r";
        if (any(r.right & Right::FsWrite))   o << "w";
        if (any(r.right & Right::FsExec))    o << "x";
        if (any(r.right & Right::NetEgress)) o << "net";
        if (r.right == Right::Unconfined)    o << "ALL";
        o << "  " << r.scope << "\n      (" << r.provenance << ")\n";
    }
    return o.str();
}

}  // namespace bastion

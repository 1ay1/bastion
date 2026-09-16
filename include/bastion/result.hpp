// bastion/result.hpp — outcomes where the failure state is unrepresentable.
//
// THE PROBLEM WITH `{bool ok; std::string error;}`
// That shape lets you build three states, two of which are lies:
//
//     {ok=true,  error=""}        fine
//     {ok=false, error="..."}     fine
//     {ok=true,  error="boom"}    a failure that reports success
//     {ok=false, error=""}        a failure with no reason
//
// Nothing stops a caller reading the value of a failed result, or forgetting to
// check `ok` at all. For a sandbox that is not a style issue: `compile()`
// returning a half-built Ruleset that someone then applies means enforcing a
// policy that was never actually valid.
//
// Result<T> collapses those four states to two. The value and the error occupy
// the same storage, exactly one exists, and reading the wrong one is a
// precondition violation rather than a silently-empty string.
//
// Deliberately NOT std::expected: this must build on the C++23 subset shipped
// by the compilers bastion targets, and the diagnostics here are tuned to the
// project's vocabulary. The interface is a strict subset of expected's, so it
// can be swapped later without touching call sites.
#pragma once

#include <cassert>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>

namespace bastion {

// A failure with a reason. Constructing one without a reason is impossible.
class Error {
public:
    explicit Error(std::string why) : why_(std::move(why)) {
        // An empty reason is the "failed but I won't say why" state that this
        // whole file exists to eliminate.
        assert(!why_.empty() && "bastion: an Error must carry a reason");
    }

    [[nodiscard]] const std::string& message() const& noexcept { return why_; }
    [[nodiscard]] std::string message() && noexcept { return std::move(why_); }

private:
    std::string why_;
};

// Either a T or an Error -- never both, never neither.
//
// [[nodiscard]] on the type: ignoring a Result is almost always a bug, and in
// this codebase an ignored failure means running unconfined.
template <class T>
class [[nodiscard]] Result {
public:
    using value_type = T;

    Result(T v) : slot_(std::move(v)) {}          // NOLINT: implicit by design
    Result(Error e) : slot_(std::move(e)) {}      // NOLINT: implicit by design

    [[nodiscard]] bool ok() const noexcept {
        return std::holds_alternative<T>(slot_);
    }
    explicit operator bool() const noexcept { return ok(); }

    // Reading the wrong alternative is a contract violation, not a silent
    // default. In a release build std::get throws rather than handing back a
    // zero-initialised value that the caller would treat as real.
    [[nodiscard]] const T& value() const& { return std::get<T>(slot_); }
    [[nodiscard]] T&& value() && { return std::get<T>(std::move(slot_)); }

    [[nodiscard]] const std::string& error() const& {
        return std::get<Error>(slot_).message();
    }

    // The common "use it or fall back" shape, without an if.
    template <class U>
    [[nodiscard]] T value_or(U&& fallback) const& {
        return ok() ? value() : static_cast<T>(std::forward<U>(fallback));
    }

private:
    std::variant<T, Error> slot_;
};

// Result<void>: an operation that either succeeded or explains why it did not.
// Replaces the `std::string apply()` idiom where "" means success -- a
// convention nothing enforces and which reads backwards at every call site.
template <>
class [[nodiscard]] Result<void> {
public:
    Result() = default;                                   // success
    Result(Error e) : err_(std::move(e)) {}               // NOLINT: by design

    [[nodiscard]] bool ok() const noexcept { return !err_.has_value(); }
    explicit operator bool() const noexcept { return ok(); }

    [[nodiscard]] const std::string& error() const& {
        assert(!ok() && "bastion: error() on a successful Result");
        return err_->message();
    }

private:
    std::optional<Error> err_;
};

using Status = Result<void>;

// Spelled-out constructors, so a call site reads as a claim about the outcome.
template <class T>
[[nodiscard]] Result<std::remove_cvref_t<T>> ok(T&& v) {
    return Result<std::remove_cvref_t<T>>{std::forward<T>(v)};
}

[[nodiscard]] inline Status ok() { return Status{}; }

[[nodiscard]] inline Error fail(std::string why) { return Error{std::move(why)}; }

}  // namespace bastion

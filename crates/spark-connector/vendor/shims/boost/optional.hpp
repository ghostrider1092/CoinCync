#pragma once
// Minimal shim: Firo's serialize.h only needs boost::optional to exist for its
// generic Serialize/Unserialize overloads. libspark never instantiates them, so
// mapping to std::optional is sufficient and keeps libspark's crypto untouched.
#include <optional>
namespace boost {
    template <class T> using optional = std::optional<T>;
    inline constexpr auto none = std::nullopt;
}

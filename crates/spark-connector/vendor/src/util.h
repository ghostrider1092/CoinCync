#pragma once
// SPIKE SHIM (replaces Firo NODE util.h — infra, NOT libspark crypto). Provides
// the light stdlib headers the original transitively pulled (libspark uses
// nothing else from it); no boost::thread / boost::filesystem / tinyformat.
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <algorithm>
#include <map>
// Safe integer comparison helper (originally in Firo util). For the sizes
// libspark compares, plain operator< is equivalent.
namespace cmp {
    template <class A, class B> constexpr bool less(A a, B b) { return a < b; }
    template <class A, class B> constexpr bool greater(A a, B b) { return a > b; }
    template <class A, class B> constexpr bool equal(A a, B b) { return a == b; }
}
namespace cmp {
    template <class A, class B> constexpr bool not_equal(A a, B b) { return a != b; }
    template <class A, class B> constexpr bool less_equal(A a, B b) { return a <= b; }
    template <class A, class B> constexpr bool greater_equal(A a, B b) { return a >= b; }
}
// Node logging — no-op in the vendored crypto (logging is not functional crypto).
#define LogPrintf(...) ((void)0)
#define LogPrint(...) ((void)0)
#ifndef FIRO_UNUSED
#define FIRO_UNUSED [[maybe_unused]]
#endif

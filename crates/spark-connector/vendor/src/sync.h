#pragma once
// SPIKE SHIM (replaces Firo NODE sync.h — threading infra, NOT libspark crypto).
// libspark uses only CCriticalSection + LOCK (params.cpp singleton). Provide a
// std::recursive_mutex-backed equivalent; no boost::thread.
#include <mutex>
typedef std::recursive_mutex CCriticalSection;
#define PASTE_(a,b) a##b
#define PASTE(a,b) PASTE_(a,b)
#define LOCK(cs) std::lock_guard<std::recursive_mutex> PASTE(_spark_lock_, __LINE__)(cs)

// CI-only probe: upstream GCC aligned-new overflow boundary and ordinary allocation.
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
int main() {
    void *p = ::operator new(128, std::align_val_t(64));
    if (!p || reinterpret_cast<std::uintptr_t>(p) % 64) return 2;
    ::operator delete(p, std::align_val_t(64));
    try {
        volatile std::size_t too_large = std::numeric_limits<std::size_t>::max();
        p = ::operator new(too_large, std::align_val_t(64));
        ::operator delete(p, std::align_val_t(64));
        return 3;
    } catch (const std::bad_alloc &) { return 0; }
}

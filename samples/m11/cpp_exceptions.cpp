/* Small-CRT PE fixture with nested C++ exception frames and .pdata unwind data. */
#include <cstdio>

#if defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

NOINLINE static void throw_from_inner_frame() {
    throw 42;
}

NOINLINE static int catch_in_middle_frame() {
    try {
        throw_from_inner_frame();
    } catch (int value) {
        return value;
    }
    return -1;
}

NOINLINE static int outer_frame() {
    return catch_in_middle_frame();
}

int main() {
    const int result = outer_frame();
    std::printf("caught=%d\n", result);
    return result == 42 ? 0 : 1;
}

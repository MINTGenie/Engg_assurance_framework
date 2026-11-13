#include "../include/ring_buffer.hpp"

#include <cassert>

int main()
{
    RingBuffer rb(4);
    std::uint8_t v = 0;
    assert(rb.push(1));
    assert(rb.pop(v));
    assert(v == 1);
    return 0;
}

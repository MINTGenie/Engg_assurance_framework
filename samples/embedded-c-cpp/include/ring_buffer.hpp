#pragma once

#include <cstddef>
#include <cstdint>

class RingBuffer {
public:
    explicit RingBuffer(std::size_t capacity);
    ~RingBuffer();
    bool push(std::uint8_t value);
    bool pop(std::uint8_t &value);
    std::size_t size() const { return count_; }

private:
    std::uint8_t *data_;
    std::size_t capacity_;
    std::size_t head_;
    std::size_t tail_;
    std::size_t count_;
    int overruns_;
};

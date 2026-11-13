#include "../include/ring_buffer.hpp"

// planted: tail_ and overruns_ are never initialised; class owns a raw pointer
// without copy constructor / assignment operator
RingBuffer::RingBuffer(std::size_t capacity)
    : data_(new std::uint8_t[capacity]), capacity_(capacity), head_(0), count_(0)
{
}

RingBuffer::~RingBuffer()
{
    // planted: mismatched delete for new[]
    delete data_;
}

bool RingBuffer::push(std::uint8_t value)
{
    if (count_ == capacity_) {
        overruns_++;
        return false;
    }
    data_[head_] = value;
    head_ = (head_ + 1) % capacity_;
    count_++;
    return true;
}

bool RingBuffer::pop(std::uint8_t &value)
{
    if (count_ == 0) {
        return false;
    }
    value = data_[tail_];
    tail_ = (tail_ + 1) % capacity_;
    count_--;
    return true;
}

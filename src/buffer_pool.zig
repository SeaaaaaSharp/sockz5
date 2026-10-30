const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

pub fn BufferPool(comptime buffer_size: usize) type {
    assert(buffer_size > 0);
    assert(buffer_size % 2 == 0);
    return struct {
        const Self = @This();

        memory: []u8,
        buffers_count: usize,
        bit_set: std.bit_set.DynamicBitSetUnmanaged,

        pub fn init(allocator: std.mem.Allocator, buffers_count: usize) std.mem.Allocator.Error!Self {
            assert(buffers_count > 0);
            // A big benefit of allocating one big block of memory is that we
            // don't need to also allocate the space for the slices themselves.
            // We can simply just point at different parts of the big block. (So no [][]u8 needed).
            const total_memory_needed: usize = buffers_count * buffer_size;
            const memory = try allocator.alloc(u8, total_memory_needed);
            errdefer allocator.free(memory);
            if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) {
                @memset(memory, 0);
            }

            const bit_set = try std.bit_set.DynamicBitSetUnmanaged.initFull(allocator, buffers_count);
            errdefer bit_set.deinit(allocator);

            const pool = Self{
                .memory = memory,
                .bit_set = bit_set,
                .buffers_count = buffers_count,
            };
            return pool;
        }

        pub fn get_slice(self: *Self) ?[]u8 {
            assert(self.memory.len % self.buffers_count == 0);
            if (self.bit_set.count() > 0) {
                return self.get_assume_capacity();
            }
            return null;
        }

        pub fn get_slice_assume_capacity(self: *Self) []u8 {
            assert(self.memory.len % self.buffers_count == 0);

            const buffer_index: usize = self.bit_set.toggleFirstSet().?;
            assert(buffer_index < self.buffers_count);

            const buffer_bytes_offset: usize = buffer_index * buffer_size;
            return self.memory[buffer_bytes_offset .. buffer_bytes_offset + buffer_size];
        }

        pub fn get_array_ptr_assume_capacity(self: *Self) *[buffer_size]u8 {
            var slice = self.get_slice_assume_capacity();
            return slice[0..buffer_size];
        }

        pub fn put(self: *Self, buffer: []u8) void {
            assert(buffer.len == buffer_size);
            assert(self.memory.len % self.buffers_count == 0);

            const free_chunks_count: usize = self.bit_set.count();
            defer assert(free_chunks_count + 1 == self.bit_set.count());

            const buffer_ptr_int: usize = @intFromPtr(buffer.ptr);
            const first_byte_ptr_int: usize = @intFromPtr(self.memory.ptr);
            const last_byte_ptr_int: usize = first_byte_ptr_int + self.memory.len;
            assert(first_byte_ptr_int <= buffer_ptr_int and buffer_ptr_int < last_byte_ptr_int);

            const buffer_bytes_offset: usize = buffer_ptr_int - first_byte_ptr_int;
            assert(buffer_bytes_offset % buffer_size == 0);

            const buffer_index: usize = buffer_bytes_offset / buffer_size;
            assert(!self.bit_set.isSet(buffer_index));
            if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) {
                @memset(buffer, 0);
            }
            self.bit_set.set(buffer_index);
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.bit_set.deinit(allocator);
            allocator.free(self.memory);
            self.* = undefined;
        }
    };
}

test BufferPool {
    // TODO:DO
}

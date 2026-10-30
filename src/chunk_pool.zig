const std = @import("std");
const assert = std.debug.assert;

/// Pool for allocating and reusing chunks of type T.
pub fn ChunkPool(comptime T: type) type {
    return struct {
        const Self = @This();

        elements: []T,
        chunk_length: u8,
        free_chunks_bit_set: std.bit_set.DynamicBitSetUnmanaged,

        /// Initializes the pool of chunks, where each chunk has length `chunk_length` and there are `count` chunks in total.
        ///
        /// So a ChunkPool(T).init(allocator, chunks_count = 2, chunk_length = 3) will look like this:
        ///
        /// {{T, T, T}, {T, T, T}}
        pub fn init(allocator: std.mem.Allocator, chunks_count: u16, chunk_length: u8) std.mem.Allocator.Error!Self {
            assert(chunk_length > 0);
            assert(chunks_count > 0);
            const elements_count: usize = @as(usize, chunk_length) * @as(usize, chunks_count);

            const elements = try allocator.alloc(T, elements_count);
            errdefer allocator.free(elements);

            const free_chunks_bit_set = try std.bit_set.DynamicBitSetUnmanaged.initFull(allocator, chunks_count);
            errdefer free_chunks_bit_set.deinit(allocator);

            return Self{
                .elements = elements,
                .chunk_length = chunk_length,
                .free_chunks_bit_set = free_chunks_bit_set,
            };
        }

        pub fn get_chunk_optional(self: *Self) ?[]T {
            return if (self.free_chunks_bit_set.count() > 0) self.get_chunk() else null;
        }

        pub fn get_chunk(self: *Self) []T {
            assert(self.elements.len % self.chunk_length == 0);
            const free_chunks_count = self.free_chunks_bit_set.count();
            defer assert(free_chunks_count == self.free_chunks_bit_set.count() + 1);

            const chunk_bit_set_index = self.free_chunks_bit_set.toggleFirstSet().?;
            const chunk_start_index = chunk_bit_set_index * self.chunk_length;
            return self.elements[chunk_start_index .. chunk_start_index + self.chunk_length];
        }

        pub fn put_chunk(self: *Self, chunk: []T) void {
            assert(self.elements.len % self.chunk_length == 0);
            assert(self.chunk_length == chunk.len);

            const free_chunks_count = self.free_chunks_bit_set.count();
            defer assert(free_chunks_count + 1 == self.free_chunks_bit_set.count());

            const first_element_ptr_int: usize = @intFromPtr(self.elements.ptr);
            const last_element_ptr_int: usize = @intFromPtr(&self.elements[self.elements.len - 1]);

            const chunk_ptr_int: usize = @intFromPtr(chunk.ptr);
            assert(first_element_ptr_int <= chunk_ptr_int and chunk_ptr_int <= last_element_ptr_int);

            // The chunk's offset from the start of the `elemenets` in bytes.
            const chunk_bytes_offset = chunk_ptr_int - first_element_ptr_int;
            assert(chunk_bytes_offset % @sizeOf(T) == 0);

            const chunk_start_index: usize = chunk_bytes_offset / @sizeOf(T);
            assert(chunk.ptr == self.elements[chunk_start_index..].ptr);

            // The chunk's index in the bit_set, mirrored in get_chunk().
            assert(chunk_start_index % self.chunk_length == 0);
            const chunk_bit_set_index: usize = chunk_start_index / self.chunk_length;
            assert(!self.free_chunks_bit_set.isSet(chunk_bit_set_index));

            self.free_chunks_bit_set.toggle(chunk_bit_set_index);
        }

        /// Should be called *after* putting all chunks back in the pool.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            assert(self.elements.len % self.chunk_length == 0);
            assert(self.free_chunks_bit_set.count() == self.free_chunks_bit_set.capacity());
            self.free_chunks_bit_set.deinit(allocator);
            allocator.free(self.elements);
            self.* = undefined;
        }
    };
}

test ChunkPool {
    inline for (1..4) |chunk_length| {
        inline for (1..4) |chunks_count| {
            const allocator = std.testing.allocator;
            const T: type = u8;
            var pool: ChunkPool(T) = try .init(allocator, chunks_count, chunk_length);
            defer pool.deinit(allocator);

            var chunks: [chunks_count][]T = undefined;
            for (0..chunks_count) |i| {
                chunks[i] = pool.get_chunk();
                assert(chunks[i].len == chunk_length);
            }

            assert(pool.get_chunk_optional() == null);
            for (0..chunks_count) |i| {
                pool.put_chunk(chunks[i]);
            }
        }
    }
}

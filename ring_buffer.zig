const std = @import("std");

const mem = std.mem;
const math = std.math;

const assert = std.debug.assert;

pub fn StaticRingBuffer(comptime T: type, comptime Counter: type, comptime capacity: usize) type {
    assert(math.isPowerOfTwo(capacity));

    return struct {
        const Self = @This();

        head: Counter = 0,
        tail: Counter = 0,
        entries: [capacity]T = undefined,

        pub usingnamespace Mixin(Self, T, Counter);
    };
}

pub fn DynamicRingBuffer(comptime T: type, comptime Counter: type) type {
    return struct {
        const Self = @This();

        head: Counter = 0,
        tail: Counter = 0,
        entries: []T,

        pub usingnamespace Mixin(Self, T, Counter);

        pub fn initCapacity(gpa: mem.Allocator, capacity: usize) !Self {
            assert(math.isPowerOfTwo(capacity));
            return Self{ .entries = try gpa.alloc(T, capacity) };
        }

        pub fn deinit(self: *Self, gpa: mem.Allocator) void {
            gpa.free(self.entries);
        }
    };
}

pub fn SliceRingBuffer(comptime T: type, comptime Counter: type) type {
    return struct {
        const Self = @This();

        head: Counter = 0,
        tail: Counter = 0,
        entries: []T,

        pub usingnamespace Mixin(Self, T);

        pub fn from(slice: []T) Self {
            assert(math.isPowerOfTwo(slice.len));
            return Self{ .entries = slice };
        }
    };
}

fn Mixin(comptime Self: type, comptime T: type, comptime Counter: type) type {
    return struct {
        /// This routine pushes an item, and optionally returns an evicted item should
        /// the insertion of the provided item overflow the existing buffer.
        pub fn pushOrNull(self: *Self, item: T) ?T {
            const evicted = evicted: {
                if (self.count() == self.entries.len) {
                    break :evicted self.pop();
                }
                break :evicted null;
            };

            self.push(item);

            return evicted;
        }

        pub fn push(self: *Self, item: T) void {
            assert(self.count() < self.entries.len);
            self.entries[self.head & (self.entries.len - 1)] = item;
            self.head +%= 1;
        }

        pub fn pushOne(self: *Self) *T {
            assert(self.count() < self.entries.len);
            const slot = &self.entries[self.head & (self.entries.len - 1)];
            self.head +%= 1;
            return slot;
        }

        pub fn prepend(self: *Self, item: T) void {
            assert(self.count() < self.entries.len);
            self.entries[(self.tail -% 1) & (self.entries.len - 1)] = item;
            self.tail -%= 1;
        }

        /// This routine pops an item from the tail of the buffer and returns it provided
        /// that the buffer is not empty.
        ///
        /// This routine is typically used in order to pop and de-initialize all items
        /// stored in the buffer.
        pub fn popOrNull(self: *Self) ?T {
            if (self.count() == 0) return null;
            return self.pop();
        }

        pub fn pop(self: *Self) T {
            assert(self.count() > 0);
            const evicted = self.entries[self.tail & (self.entries.len - 1)];
            self.tail +%= 1;
            return evicted;
        }

        pub fn get(self: Self, i: Counter) ?T {
            if (i < self.tail or i >= self.head) return null;
            return self.entries[i & (self.entries.len - 1)];
        }

        pub fn count(self: Self) usize {
            return self.head -% self.tail;
        }

        pub fn latest(self: Self) ?T {
            if (self.count() == 0) return null;
            return self.entries[(self.head -% 1) & (self.entries.len - 1)];
        }

        pub fn oldest(self: *Self) ?T {
            if (self.count() == 0) return null;
            return self.entries[self.tail & (self.entries.len - 1)];
        }
    };
}

const std = @import("std");

const mem = std.mem;
const math = std.math;
const builtin = std.builtin;
const testing = std.testing;

const assert = std.debug.assert;

const spsc = @This();

pub const cache_line_length = switch (builtin.cpu.arch) {
    .x86_64, .aarch64, .powerpc64 => 128,
    .arm, .mips, .mips64, .riscv64 => 32,
    .s390x => 256,
    else => 64,
};

pub fn BoundedQueue(comptime T: type, comptime capacity: comptime_int) type {
    assert(math.isPowerOfTwo(capacity));

    const mask = capacity - 1;

    return struct {
        const Self = @This();

        buffer: [*]T align(cache_line_length),
        head: usize align(cache_line_length),
        tail: usize align(cache_line_length),

        pub fn init(gpa: *mem.Allocator) !Self {
            const buffer = try gpa.create([capacity]T);
            return Self{ .buffer = buffer, .head = 0, .tail = 0 };
        }

        pub fn deinit(self: *Self, gpa: *mem.Allocator) void {
            gpa.destroy(@ptrCast(*[capacity]T, self.buffer));
        }

        pub fn push(self: *Self, value: T) bool {
            const head = @atomicLoad(usize, &self.head, .Monotonic);
            const tail = @atomicLoad(usize, &self.tail, .Acquire);
            if (head +% 1 -% tail > capacity) return false;
            self.buffer[head & mask] = value;
            @atomicStore(usize, &self.head, head +% 1, .Release);
            return true;
        }

        pub fn pop(self: *Self) ?T {
            const tail = @atomicLoad(usize, &self.tail, .Monotonic);
            const head = @atomicLoad(usize, &self.head, .Acquire);
            if (tail -% head == 0) return null;
            const value = self.buffer[tail & mask];
            @atomicStore(usize, &self.tail, tail +% 1, .Release);
            return value;
        }
    };
}

pub fn UnboundedQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        pub const Node = struct {
            next: ?*Self.Node,
            value: T,
        };

        tail: *Self.Node align(cache_line_length),
        head: *Self.Node,
        first_: *Self.Node,
        tail_copy_: *Self.Node,

        pub fn init(gpa: *mem.Allocator) !Self {
            const node = try gpa.create(Self.Node);
            node.next = null;

            var self: Self = undefined;
            self.tail = node;
            self.head = node;
            self.first_ = node;
            self.tail_copy_ = node;

            return self;
        }

        pub fn deinit(self: *Self, gpa: *mem.Allocator) void {
            var it: ?*Self.Node = self.first_;
            while (it) |node| {
                it = node.next;
                gpa.destroy(node);
            }
        }

        pub fn push(self: *Self, gpa: *mem.Allocator, value: T) !void {
            const node = try self.createNode(gpa);
            node.* = .{ .next = null, .value = value };

            @atomicStore(?*Self.Node, &self.head.next, node, .Release);
            self.head = node;
        }

        pub fn pop(self: *Self) ?T {
            if (@atomicLoad(?*Node, &self.tail.next, .Acquire)) |next_tail| {
                const value = next_tail.value;
                @atomicStore(*Node, &self.tail, next_tail, .Release);
                return value;
            }
            return null;
        }

        fn createNode(self: *Self, gpa: *mem.Allocator) !*Self.Node {
            if (self.first_ != self.tail_copy_) {
                const node = self.first_;
                self.first_ = self.first_.next.?;
                return node;
            }
            self.tail_copy_ = @atomicLoad(*Node, &self.tail, .Acquire);
            if (self.first_ != self.tail_copy_) {
                const node = self.first_;
                self.first_ = self.first_.next.?;
                return node;
            }
            return gpa.create(Node);
        }
    };
}

test "spsc/bounded_queue: push and pop" {
    var queue = try spsc.BoundedQueue(usize, 2).init(testing.allocator);
    defer queue.deinit(testing.allocator);

    try testing.expect(queue.push(1));
    try testing.expect(queue.push(2));
    try testing.expect(!queue.push(3));

    try testing.expectEqual(@as(?usize, 1), queue.pop());
    try testing.expectEqual(@as(?usize, 2), queue.pop());

    try testing.expect(queue.push(3));
    try testing.expect(queue.push(4));
    try testing.expect(!queue.push(5));

    try testing.expectEqual(@as(?usize, 3), queue.pop());
    try testing.expectEqual(@as(?usize, 4), queue.pop());
    try testing.expectEqual(@as(?usize, null), queue.pop());
}

test "spsc/bounded_queue: fifo behavior" {
    if (builtin.single_threaded) return error.SkipZigTest;

    const Context = struct {
        queue: *spsc.BoundedQueue(usize, 256),

        pub fn runProducer(self: @This()) !void {
            var i: usize = 0;
            while (i < 1_000_000) : (i += 1) {
                while (!self.queue.push(i)) {
                    continue;
                }
            }
        }

        pub fn runConsumer(self: @This()) !void {
            var i: usize = 0;
            while (i < 1_000_000) : (i += 1) {
                const j = while (true) {
                    if (self.queue.pop()) |j| {
                        break j;
                    }
                } else unreachable;

                try testing.expectEqual(@as(?usize, i), j);
            }
        }
    };

    var queue = try spsc.BoundedQueue(usize, 256).init(testing.allocator);
    defer queue.deinit(testing.allocator);

    const ctx: Context = .{ .queue = &queue };

    {
        const producer_thread = try std.Thread.spawn(.{}, Context.runProducer, .{ctx});
        defer producer_thread.join();

        const consumer_thread = try std.Thread.spawn(.{}, Context.runConsumer, .{ctx});
        defer consumer_thread.join();
    }

    try testing.expectEqual(@as(?usize, null), queue.pop());
}

test "spsc/unbounded_queue: push and pop" {
    var queue = try spsc.UnboundedQueue(usize).init(testing.allocator);
    defer queue.deinit(testing.allocator);

    try queue.push(testing.allocator, 1);
    try queue.push(testing.allocator, 2);

    try testing.expectEqual(@as(?usize, 1), queue.pop());
    try testing.expectEqual(@as(?usize, 2), queue.pop());

    try queue.push(testing.allocator, 3);
    try queue.push(testing.allocator, 4);

    try testing.expectEqual(@as(?usize, 3), queue.pop());
    try testing.expectEqual(@as(?usize, 4), queue.pop());
    try testing.expectEqual(@as(?usize, null), queue.pop());
}

test "spsc/unboundeded_queue: fifo behavior" {
    if (builtin.single_threaded) return error.SkipZigTest;

    const Context = struct {
        gpa: *mem.Allocator,
        queue: *spsc.UnboundedQueue(usize),

        pub fn runProducer(self: @This()) !void {
            var i: usize = 0;
            while (i < 1_000_000) : (i += 1) {
                try self.queue.push(self.gpa, i);
            }
        }

        pub fn runConsumer(self: @This()) !void {
            var i: usize = 0;
            while (i < 1_000_000) : (i += 1) {
                const j = while (true) {
                    if (self.queue.pop()) |j| {
                        break j;
                    }
                } else unreachable;

                try testing.expectEqual(@as(?usize, i), j);
            }
        }
    };

    var queue = try spsc.UnboundedQueue(usize).init(testing.allocator);
    defer queue.deinit(testing.allocator);

    const ctx: Context = .{ .gpa = testing.allocator, .queue = &queue };

    {
        const producer_thread = try std.Thread.spawn(.{}, Context.runProducer, .{ctx});
        defer producer_thread.join();

        const consumer_thread = try std.Thread.spawn(.{}, Context.runConsumer, .{ctx});
        defer consumer_thread.join();
    }

    try testing.expectEqual(@as(?usize, null), queue.pop());
}

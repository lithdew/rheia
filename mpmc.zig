const std = @import("std");

const os = std.os;
const mem = std.mem;
const math = std.math;
const atomic = std.atomic;
const builtin = std.builtin;
const testing = std.testing;

const Atomic = std.atomic.Atomic;

const assert = std.debug.assert;

const mpmc = @This();

pub const cache_line_length = switch (builtin.cpu.arch) {
    .x86_64, .aarch64, .powerpc64 => 128,
    .arm, .mips, .mips64, .riscv64 => 32,
    .s390x => 256,
    else => 64,
};

pub fn Ring(comptime T: type, comptime capacity: comptime_int) type {
    assert(math.isPowerOfTwo(capacity));

    const mask = capacity - 1;

    return struct {
        const Self = @This();

        prod_head: Atomic(u32) = .{ .value = 0 },
        prod_tail: Atomic(u32) = .{ .value = 0 },

        cons_head: Atomic(u32) align(cache_line_length) = .{ .value = 0 },
        cons_tail: Atomic(u32) = .{ .value = 0 },

        entries: *[capacity]T align(cache_line_length),

        pub fn init(gpa: *mem.Allocator) !Self {
            return Self{ .entries = try gpa.create([capacity]T) };
        }

        pub fn deinit(self: *Self, gpa: *mem.Allocator) void {
            gpa.destroy(self.entries);
        }

        pub inline fn pushMP(self: *Self, item: T) bool {
            var prod_head: u32 = self.prod_head.loadUnchecked();
            var prod_next: u32 = undefined;

            while (true) {
                const cons_tail = self.cons_tail.loadUnchecked();
                if (prod_head -% cons_tail >= capacity) {
                    @fence(.Acquire);
                    if (prod_head == self.prod_head.loadUnchecked() and cons_tail == self.cons_tail.loadUnchecked()) {
                        return false;
                    }
                    prod_head = self.prod_head.loadUnchecked();
                    continue;
                }

                prod_next = prod_head +% 1;
                prod_head = self.prod_head.tryCompareAndSwap(
                    prod_head,
                    prod_next,
                    .Acquire,
                    .Monotonic,
                ) orelse break;
            }

            self.entries[prod_head & mask] = item;
            while (self.prod_tail.loadUnchecked() != prod_head) {
                os.sched_yield() catch {};
            }

            self.prod_tail.store(prod_next, .Release);
            return true;
        }

        pub inline fn pushSP(self: *Self, item: T) bool {
            const prod_head = self.prod_head.load(.Acquire);
            const cons_tail = self.cons_tail.loadUnchecked();

            if (prod_head -% cons_tail >= capacity) {
                return false;
            }

            const prod_next = prod_head +% 1;
            self.prod_head.storeUnchecked(prod_next);
            self.entries[prod_head & mask] = item;
            self.prod_tail.store(prod_next, .Release);
            return true;
        }

        pub inline fn popMC(self: *Self) ?T {
            atomic.compilerFence(.SeqCst);

            var cons_head: u32 = self.cons_head.loadUnchecked();
            var cons_next: u32 = undefined;
            while (true) {
                if (cons_head == self.prod_tail.loadUnchecked()) {
                    return null;
                }
                cons_next = cons_head +% 1;
                cons_head = self.cons_head.tryCompareAndSwap(
                    cons_head,
                    cons_next,
                    .Acquire,
                    .Monotonic,
                ) orelse break;
            }

            const item = self.entries[cons_head & mask];
            while (self.cons_tail.loadUnchecked() != cons_head) {
                os.sched_yield() catch {};
            }

            self.cons_tail.store(cons_next, .Release);
            return item;
        }

        pub inline fn popSC(self: *Self) ?T {
            const cons_head = self.cons_head.load(.Acquire);
            const prod_tail = self.prod_tail.loadUnchecked();
            if (cons_head == prod_tail) return null;

            const cons_next = cons_head +% 1;
            self.cons_head.storeUnchecked(cons_next);
            const item = self.entries[cons_head & mask];
            self.cons_tail.store(cons_next, .Release);
            return item;
        }

        pub inline fn advanceSC(self: *Self) void {
            const cons_head = self.cons_head.loadUnchecked();
            const prod_tail = self.prod_tail.loadUnchecked();
            const cons_next = cons_head +% 1;
            if (cons_head == prod_tail) return;
            self.cons_head.storeUnchecked(cons_next);
            self.cons_tail.storeUnchecked(cons_next);
        }

        pub inline fn putBackSC(self: *Self, item: T) void {
            assert(self.cons_head.loadUnchecked() != self.prod_tail.loadUnchecked());
            self.entries[self.cons_head.loadUnchecked() & mask] = item;
        }

        pub inline fn peekSC(self: *Self) ?T {
            if (self.cons_head.loadUnchecked() == self.prod_tail.loadUnchecked()) {
                return null;
            }
            return self.entries[self.cons_head.loadUnchecked() & mask];
        }

        pub inline fn isFull(self: *Self) bool {
            return self.prod_head.loadUnchecked() +% 1 == self.cons_tail.loadUnchecked();
        }

        pub inline fn isEmpty(self: *Self) bool {
            return self.cons_head.loadUnchecked() == self.prod_tail.loadUnchecked();
        }

        pub inline fn count(self: *Self) usize {
            return (capacity +% self.prod_tail.loadUnchecked() -% self.cons_tail.loadUnchecked()) & mask;
        }
    };
}

test "ring: spsc: push and pop with a capacity of 2" {
    var queue = try mpmc.Ring(usize, 2).init(testing.allocator);
    defer queue.deinit(testing.allocator);

    try testing.expect(queue.pushSP(1));
    try testing.expect(queue.pushSP(2));
    try testing.expect(!queue.pushSP(3));

    try testing.expectEqual(@as(?usize, 1), queue.popSC());
    try testing.expectEqual(@as(?usize, 2), queue.popSC());

    try testing.expect(queue.pushSP(3));
    try testing.expect(queue.pushSP(4));
    try testing.expect(!queue.pushSP(5));

    try testing.expectEqual(@as(?usize, 3), queue.popSC());
    try testing.expectEqual(@as(?usize, 4), queue.popSC());
    try testing.expectEqual(@as(?usize, null), queue.popSC());
}

test "ring: spsc: push and pop with a capacity of 4" {
    var queue = try mpmc.Ring(usize, 4).init(testing.allocator);
    defer queue.deinit(testing.allocator);

    try testing.expect(queue.pushSP(1));
    try testing.expect(queue.pushSP(2));
    try testing.expect(queue.pushSP(3));
    try testing.expect(queue.pushSP(4));
    try testing.expect(!queue.pushSP(5));

    try testing.expectEqual(@as(?usize, 1), queue.popSC());
    try testing.expectEqual(@as(?usize, 2), queue.popSC());
    try testing.expectEqual(@as(?usize, 3), queue.popSC());
    try testing.expectEqual(@as(?usize, 4), queue.popSC());
    try testing.expectEqual(@as(?usize, null), queue.popSC());

    try testing.expect(queue.pushSP(5));
    try testing.expect(queue.pushSP(6));
    try testing.expect(queue.pushSP(7));
    try testing.expect(queue.pushSP(8));
    try testing.expect(!queue.pushSP(9));

    try testing.expectEqual(@as(?usize, 5), queue.popSC());
    try testing.expectEqual(@as(?usize, 6), queue.popSC());
    try testing.expectEqual(@as(?usize, 7), queue.popSC());
    try testing.expectEqual(@as(?usize, 8), queue.popSC());
    try testing.expectEqual(@as(?usize, null), queue.popSC());
}

test "ring: {s,m}pmc: push and pop with a capacity of 2" {
    var queue = try mpmc.Ring(usize, 2).init(testing.allocator);
    defer queue.deinit(testing.allocator);

    try testing.expect(queue.pushMP(1));
    try testing.expect(queue.pushMP(2));
    try testing.expect(!queue.pushMP(3));

    try testing.expectEqual(@as(?usize, 1), queue.popMC());
    try testing.expectEqual(@as(?usize, 2), queue.popMC());

    try testing.expect(queue.pushMP(3));
    try testing.expect(queue.pushMP(4));
    try testing.expect(!queue.pushMP(5));

    try testing.expectEqual(@as(?usize, 3), queue.popMC());
    try testing.expectEqual(@as(?usize, 4), queue.popMC());
    try testing.expectEqual(@as(?usize, null), queue.popMC());
}

test "ring: {s,m}pmc: push and pop with a capacity of 4" {
    var queue = try mpmc.Ring(usize, 4).init(testing.allocator);
    defer queue.deinit(testing.allocator);

    try testing.expect(queue.pushMP(1));
    try testing.expect(queue.pushMP(2));
    try testing.expect(queue.pushMP(3));
    try testing.expect(queue.pushMP(4));
    try testing.expect(!queue.pushMP(5));

    try testing.expectEqual(@as(?usize, 1), queue.popMC());
    try testing.expectEqual(@as(?usize, 2), queue.popMC());
    try testing.expectEqual(@as(?usize, 3), queue.popMC());
    try testing.expectEqual(@as(?usize, 4), queue.popMC());
    try testing.expectEqual(@as(?usize, null), queue.popMC());

    try testing.expect(queue.pushMP(5));
    try testing.expect(queue.pushMP(6));
    try testing.expect(queue.pushMP(7));
    try testing.expect(queue.pushMP(8));
    try testing.expect(!queue.pushMP(9));

    try testing.expectEqual(@as(?usize, 5), queue.popMC());
    try testing.expectEqual(@as(?usize, 6), queue.popMC());
    try testing.expectEqual(@as(?usize, 7), queue.popMC());
    try testing.expectEqual(@as(?usize, 8), queue.popMC());
    try testing.expectEqual(@as(?usize, null), queue.popMC());
}

test "ring: {s,m}pmc: push and pop with a capacity of 4" {
    var queue = try mpmc.Ring(usize, 4).init(testing.allocator);
    defer queue.deinit(testing.allocator);

    try testing.expect(queue.pushMP(1));
    try testing.expect(queue.pushMP(2));
    try testing.expect(queue.pushMP(3));
    try testing.expect(queue.pushMP(4));
    try testing.expect(!queue.pushMP(5));

    try testing.expectEqual(@as(?usize, 1), queue.popMC());
    try testing.expectEqual(@as(?usize, 2), queue.popMC());
    try testing.expectEqual(@as(?usize, 3), queue.popMC());
    try testing.expectEqual(@as(?usize, 4), queue.popMC());
    try testing.expectEqual(@as(?usize, null), queue.popMC());

    try testing.expect(queue.pushMP(5));
    try testing.expect(queue.pushMP(6));
    try testing.expect(queue.pushMP(7));
    try testing.expect(queue.pushMP(8));
    try testing.expect(!queue.pushMP(9));

    try testing.expectEqual(@as(?usize, 5), queue.popMC());
    try testing.expectEqual(@as(?usize, 6), queue.popMC());
    try testing.expectEqual(@as(?usize, 7), queue.popMC());
    try testing.expectEqual(@as(?usize, 8), queue.popMC());
    try testing.expectEqual(@as(?usize, null), queue.popMC());
}

test "ring: spsc: fifo behavior" {
    if (builtin.single_threaded) return error.SkipZigTest;

    const Context = struct {
        ring: *mpmc.Ring(usize, 256),

        pub fn runProducer(self: @This()) !void {
            var i: usize = 0;
            while (i < 1_000_000) : (i += 1) {
                while (!self.ring.pushSP(i)) {
                    continue;
                }
            }
        }

        pub fn runConsumer(self: @This()) !void {
            var i: usize = 0;
            while (i < 1_000_000) : (i += 1) {
                const j = while (true) {
                    if (self.ring.popSC()) |j| {
                        break j;
                    }
                } else unreachable;

                try testing.expectEqual(@as(?usize, i), j);
            }
        }
    };

    var ring = try mpmc.Ring(usize, 256).init(testing.allocator);
    defer ring.deinit(testing.allocator);

    const ctx: Context = .{ .ring = &ring };

    {
        const producer_thread = try std.Thread.spawn(.{}, Context.runProducer, .{ctx});
        defer producer_thread.join();

        const consumer_thread = try std.Thread.spawn(.{}, Context.runConsumer, .{ctx});
        defer consumer_thread.join();
    }

    try testing.expectEqual(@as(?usize, null), ring.popSC());
}

test "ring: mpsc behavior" {
    if (builtin.single_threaded) return error.SkipZigTest;

    const num_producers = 8;
    const num_items_per_producer = 100_000;

    const Context = struct {
        ring: *mpmc.Ring(usize, 256),

        pub fn runProducer(self: @This()) !void {
            var i: usize = 0;
            while (i < num_items_per_producer) : (i += 1) {
                while (!self.ring.pushMP(i)) {
                    continue;
                }
            }
        }

        pub fn runConsumer(self: @This()) !void {
            var i: usize = 0;
            while (i < num_producers * num_items_per_producer) : (i += 1) {
                while (true) {
                    if (self.ring.popSC()) |_| {
                        break;
                    }
                }
            }
        }
    };

    var ring = try mpmc.Ring(usize, 256).init(testing.allocator);
    defer ring.deinit(testing.allocator);

    const ctx: Context = .{ .ring = &ring };

    {
        var producer_threads: [num_producers]std.Thread = undefined;

        var producer_thread_index: usize = 0;
        defer for (producer_threads[0..producer_thread_index]) |*producer_thread| producer_thread.join();

        while (producer_thread_index < producer_threads.len) : (producer_thread_index += 1) {
            producer_threads[producer_thread_index] = try std.Thread.spawn(.{}, Context.runProducer, .{ctx});
        }

        const consumer_thread = try std.Thread.spawn(.{}, Context.runConsumer, .{ctx});
        defer consumer_thread.join();
    }

    try testing.expectEqual(@as(?usize, null), ring.popSC());
}

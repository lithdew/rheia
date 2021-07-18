const std = @import("std");

const os = std.os;
const mem = std.mem;
const atomic = std.atomic;
const builtin = std.builtin;
const testing = std.testing;

const assert = std.debug.assert;

const mpsc = @This();

pub const cache_line_length = switch (builtin.cpu.arch) {
    .x86_64, .aarch64, .powerpc64 => 128,
    .arm, .mips, .mips64, .riscv64 => 32,
    .s390x => 256,
    else => 64,
};

pub fn UnboundedStack(comptime T: type) type {
    return struct {
        const Self = @This();

        pub const Node = struct {
            next: ?*Self.Node = null,
            value: T,
        };

        stack: ?*Self.Node align(cache_line_length) = null,

        pub fn push(self: *Self, node: *Self.Node) void {
            return self.pushBatch(node, node);
        }

        pub fn pushBatch(self: *Self, head: *Self.Node, tail: *Self.Node) void {
            var stack = @atomicLoad(?*Self.Node, &self.stack, .Monotonic);
            while (true) {
                tail.next = stack;
                stack = @cmpxchgWeak(
                    ?*Self.Node,
                    &self.stack,
                    stack,
                    head,
                    .Release,
                    .Monotonic,
                ) orelse return;
            }
        }

        pub fn popBatch(self: *Self) ?*Self.Node {
            if (self.isEmpty()) return null;
            return @atomicRmw(?*Self.Node, &self.stack, .Xchg, null, .Acquire);
        }

        pub fn isEmpty(self: *Self) bool {
            return @atomicLoad(?*Self.Node, &self.stack, .Monotonic) == null;
        }
    };
}

pub fn UnboundedQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        pub const Node = struct {
            pub const Batch = struct {
                pub const Iterator = struct {
                    batch: Self.Node.Batch,

                    pub fn next(self: *Self.Node.Batch.Iterator) ?T {
                        if (self.batch.count == 0) return null;
                        const front = self.batch.front orelse unreachable;
                        self.batch.front = front.next;
                        self.batch.count -= 1;
                        return front.value;
                    }
                };

                front: ?*Self.Node = null,
                last: ?*Self.Node = null,
                count: usize = 0,

                pub fn iterator(self: Self.Node.Batch) Self.Node.Batch.Iterator {
                    return .{ .batch = self };
                }
            };

            next: ?*Self.Node = null,
            value: T,
        };

        pub const queue_padding_length = cache_line_length / 2;

        back: ?*Self.Node align(queue_padding_length) = null,
        count: usize = 0,
        front: Self.Node align(queue_padding_length) = .{ .value = undefined },

        pub fn push(self: *Self, src: *Self.Node) void {
            assert(@atomicRmw(usize, &self.count, .Add, 1, .Release) >= 0);

            src.next = null;
            const old_back = @atomicRmw(?*Self.Node, &self.back, .Xchg, src, .AcqRel) orelse &self.front;
            old_back.next = src;
        }

        pub fn pushBatch(self: *Self, first: *Self.Node, last: *Self.Node, count: usize) void {
            assert(@atomicRmw(usize, &self.count, .Add, count, .Release) >= 0);

            last.next = null;
            const old_back = @atomicRmw(?*Self.Node, &self.back, .Xchg, last, .AcqRel) orelse &self.front;
            old_back.next = first;
        }

        pub fn pop(self: *Self) ?*Self.Node {
            const first = @atomicLoad(?*Self.Node, &self.front.next, .Acquire) orelse return null;
            if (@atomicLoad(?*Self.Node, &first.next, .Acquire)) |next| {
                @atomicStore(?*Self.Node, &self.front.next, next, .Monotonic);
                assert(@atomicRmw(usize, &self.count, .Sub, 1, .Monotonic) >= 1);
                return first;
            }
            const last = @atomicLoad(?*Self.Node, &self.back, .Acquire) orelse &self.front;
            if (first != last) return null;
            @atomicStore(?*Self.Node, &self.front.next, null, .Monotonic);
            if (@cmpxchgStrong(?*Self.Node, &self.back, last, &self.front, .AcqRel, .Acquire) == null) {
                assert(@atomicRmw(usize, &self.count, .Sub, 1, .Monotonic) >= 1);
                return first;
            }
            var next = @atomicLoad(?*Self.Node, &first.next, .Acquire);
            while (next == null) : (atomic.spinLoopHint()) {
                next = @atomicLoad(?*Self.Node, &first.next, .Acquire);
            }
            @atomicStore(?*Self.Node, &self.front.next, next, .Monotonic);
            assert(@atomicRmw(usize, &self.count, .Sub, 1, .Monotonic) >= 1);
            return first;
        }

        pub fn popBatch(self: *Self) Self.Node.Batch {
            var batch: Self.Node.Batch = .{};

            var front = @atomicLoad(?*Self.Node, &self.front.next, .Acquire) orelse return batch;
            batch.front = front;

            var next = @atomicLoad(?*Self.Node, &front.next, .Acquire);
            while (next) |next_node| {
                batch.count += 1;
                batch.last = front;

                front = next_node;
                next = @atomicLoad(?*Self.Node, &next_node.next, .Acquire);
            }

            const last = @atomicLoad(?*Self.Node, &self.back, .Acquire) orelse &self.front;
            if (front != last) {
                @atomicStore(?*Self.Node, &self.front.next, front, .Release);
                assert(@atomicRmw(usize, &self.count, .Sub, batch.count, .Monotonic) >= batch.count);
                return batch;
            }

            @atomicStore(?*Self.Node, &self.front.next, null, .Monotonic);
            if (@cmpxchgStrong(?*Self.Node, &self.back, last, &self.front, .AcqRel, .Acquire) == null) {
                batch.count += 1;
                batch.last = front;
                assert(@atomicRmw(usize, &self.count, .Sub, batch.count, .Monotonic) >= batch.count);
                return batch;
            }

            next = @atomicLoad(?*Self.Node, &front.next, .Acquire);
            while (next == null) : (atomic.spinLoopHint()) {
                next = @atomicLoad(?*Self.Node, &front.next, .Acquire);
            }

            batch.count += 1;
            @atomicStore(?*Self.Node, &self.front.next, next, .Monotonic);
            batch.last = front;
            assert(@atomicRmw(usize, &self.count, .Sub, batch.count, .Monotonic) >= batch.count);
            return batch;
        }

        pub fn peek(self: *Self) usize {
            const count = @atomicLoad(usize, &self.count, .Acquire);
            assert(count >= 0);
            return count;
        }

        pub fn isEmpty(self: *Self) bool {
            return self.peek() == 0;
        }
    };
}

test "mpsc/unbounded_stack: push and pop" {
    if (builtin.single_threaded) return error.SkipZigTest;

    const cpu_count = try std.Thread.getCpuCount();
    if (cpu_count < 2) return error.SkipZigTest;

    const num_items_per_producer = 100_000;

    const Context = struct {
        gpa: *mem.Allocator,
        stack: *mpsc.UnboundedStack(usize),

        pub fn runProducer(self: @This()) !void {
            var i: usize = 0;
            while (i < num_items_per_producer) : (i += 1) {
                const node = try self.gpa.create(mpsc.UnboundedStack(usize).Node);
                node.* = .{ .value = i };
                self.stack.push(node);
            }
        }

        pub fn runConsumer(self: @This(), num_producers: usize) void {
            var remaining = num_producers * num_items_per_producer;
            while (remaining > 0) {
                var it = self.stack.popBatch();
                while (it) |node| {
                    it = node.next;
                    self.gpa.destroy(node);
                    remaining -= 1;
                }
            }
        }
    };

    var stack: mpsc.UnboundedStack(usize) = .{};

    const ctx: Context = .{ .gpa = testing.allocator, .stack = &stack };

    {
        var producer_threads = try std.ArrayListUnmanaged(std.Thread).initCapacity(testing.allocator, cpu_count - 1);
        defer producer_threads.deinit(testing.allocator);

        var producer_thread_index: usize = 0;
        defer for (producer_threads.items[0..producer_thread_index]) |producer_thread| producer_thread.join();

        while (producer_thread_index < cpu_count - 1) : (producer_thread_index += 1) {
            producer_threads.addOneAssumeCapacity().* = try std.Thread.spawn(.{}, Context.runProducer, .{ctx});
        }

        const consumer_thread = try std.Thread.spawn(.{}, Context.runConsumer, .{ ctx, producer_threads.items.len });
        defer consumer_thread.join();
    }

    try testing.expectEqual(@as(?*mpsc.UnboundedStack(usize).Node, null), stack.popBatch());
    try testing.expect(stack.isEmpty());
}

test "mpsc/unbounded_queue: push and pop" {
    if (builtin.single_threaded) return error.SkipZigTest;

    const cpu_count = try std.Thread.getCpuCount();
    if (cpu_count < 2) return error.SkipZigTest;

    const num_items_per_producer = 100_000;

    const Context = struct {
        gpa: *mem.Allocator,
        queue: *mpsc.UnboundedQueue(usize),

        pub fn runProducer(self: @This()) !void {
            var i: usize = 0;
            while (i < num_items_per_producer) : (i += 1) {
                const node = try self.gpa.create(mpsc.UnboundedQueue(usize).Node);
                node.* = .{ .value = i };
                self.queue.push(node);
            }
        }

        pub fn runConsumer(self: @This(), num_producers: usize) void {
            var remaining = num_producers * num_items_per_producer;
            while (remaining > 0) : (remaining -= 1) {
                self.gpa.destroy(
                    while (true) {
                        if (self.queue.pop()) |node| {
                            break node;
                        }
                    } else unreachable,
                );
            }
        }
    };

    var queue: mpsc.UnboundedQueue(usize) = .{};

    const ctx: Context = .{ .gpa = testing.allocator, .queue = &queue };

    {
        var producer_threads = try std.ArrayListUnmanaged(std.Thread).initCapacity(testing.allocator, cpu_count - 1);
        defer producer_threads.deinit(testing.allocator);

        var producer_thread_index: usize = 0;
        defer for (producer_threads.items[0..producer_thread_index]) |producer_thread| producer_thread.join();

        while (producer_thread_index < cpu_count - 1) : (producer_thread_index += 1) {
            producer_threads.addOneAssumeCapacity().* = try std.Thread.spawn(.{}, Context.runProducer, .{ctx});
        }

        const consumer_thread = try std.Thread.spawn(.{}, Context.runConsumer, .{ ctx, producer_threads.items.len });
        defer consumer_thread.join();
    }

    try testing.expectEqual(@as(?*mpsc.UnboundedQueue(usize).Node, null), queue.pop());
    try testing.expect(queue.popBatch().iterator().next() == null);
    try testing.expect(queue.popBatch().count == 0);

    try testing.expectEqual(@as(usize, 0), queue.peek());
}

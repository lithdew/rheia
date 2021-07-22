const std = @import("std");

const os = std.os;
const mem = std.mem;
const meta = std.meta;
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

pub fn UnboundedStack(comptime T: type, comptime next_field: meta.FieldEnum(T)) type {
    const next = meta.fieldInfo(T, next_field).name;

    return struct {
        const Self = @This();

        stack: ?*T align(cache_line_length) = null,

        pub fn push(self: *Self, node: *T) void {
            return self.pushBatch(node, node);
        }

        pub fn pushBatch(self: *Self, head: *T, tail: *T) void {
            var stack = @atomicLoad(?*T, &self.stack, .Monotonic);
            while (true) {
                @field(tail, next) = stack;
                stack = @cmpxchgWeak(
                    ?*T,
                    &self.stack,
                    stack,
                    head,
                    .Release,
                    .Monotonic,
                ) orelse return;
            }
        }

        pub fn popBatch(self: *Self) ?*T {
            if (self.isEmpty()) return null;
            return @atomicRmw(?*T, &self.stack, .Xchg, null, .Acquire);
        }

        pub fn isEmpty(self: *Self) bool {
            return @atomicLoad(?*T, &self.stack, .Monotonic) == null;
        }
    };
}

pub fn UnboundedQueue(comptime T: type, comptime next_field: meta.FieldEnum(T)) type {
    const next = meta.fieldInfo(T, next_field).name;

    return struct {
        const Self = @This();

        pub const Batch = struct {
            pub const Iterator = struct {
                batch: Self.Batch,

                pub fn next(self: *Self.Batch.Iterator) ?*T {
                    if (self.batch.count == 0) return null;
                    const front = self.batch.front orelse unreachable;
                    self.batch.front = @field(front, next);
                    self.batch.count -= 1;
                    return front;
                }
            };

            front: ?*T = null,
            last: ?*T = null,
            count: usize = 0,

            pub fn iterator(self: Self.Batch) Self.Batch.Iterator {
                return .{ .batch = self };
            }
        };

        pub const queue_padding_length = cache_line_length / 2;

        back: ?*T align(queue_padding_length) = null,
        count: usize = 0,
        front: T align(queue_padding_length) = init: {
            var stub: T = undefined;
            @field(stub, next) = null;
            break :init stub;
        },

        pub fn push(self: *Self, src: *T) void {
            assert(@atomicRmw(usize, &self.count, .Add, 1, .Release) >= 0);

            @field(src, next) = null;
            const old_back = @atomicRmw(?*T, &self.back, .Xchg, src, .AcqRel) orelse &self.front;
            @field(old_back, next) = src;
        }

        pub fn pushBatch(self: *Self, first: *T, last: *T, count: usize) void {
            assert(@atomicRmw(usize, &self.count, .Add, count, .Release) >= 0);

            @field(last, next) = null;
            const old_back = @atomicRmw(?*T, &self.back, .Xchg, last, .AcqRel) orelse &self.front;
            @field(old_back, next) = first;
        }

        pub fn pop(self: *Self) ?*T {
            const first = @atomicLoad(?*T, &@field(self.front, next), .Acquire) orelse return null;
            if (@atomicLoad(?*T, &@field(first, next), .Acquire)) |next_item| {
                @atomicStore(?*T, &@field(self.front, next), next_item, .Monotonic);
                assert(@atomicRmw(usize, &self.count, .Sub, 1, .Monotonic) >= 1);
                return first;
            }
            const last = @atomicLoad(?*T, &self.back, .Acquire) orelse &self.front;
            if (first != last) return null;
            @atomicStore(?*T, &@field(self.front, next), null, .Monotonic);
            if (@cmpxchgStrong(?*T, &self.back, last, &self.front, .AcqRel, .Acquire) == null) {
                assert(@atomicRmw(usize, &self.count, .Sub, 1, .Monotonic) >= 1);
                return first;
            }
            var next_item = @atomicLoad(?*T, &@field(first, next), .Acquire);
            while (next_item == null) : (atomic.spinLoopHint()) {
                next_item = @atomicLoad(?*T, &@field(first, next), .Acquire);
            }
            @atomicStore(?*T, &@field(self.front, next), next_item, .Monotonic);
            assert(@atomicRmw(usize, &self.count, .Sub, 1, .Monotonic) >= 1);
            return first;
        }

        pub fn popBatch(self: *Self) Self.Batch {
            var batch: Self.Batch = .{};

            var front = @atomicLoad(?*T, &@field(self.front, next), .Acquire) orelse return batch;
            batch.front = front;

            var next_item = @atomicLoad(?*T, &@field(front, next), .Acquire);
            while (next_item) |next_node| : (next_item = @atomicLoad(?*T, &@field(next_node, next), .Acquire)) {
                batch.count += 1;
                batch.last = front;

                front = next_node;
            }

            const last = @atomicLoad(?*T, &self.back, .Acquire) orelse &self.front;
            if (front != last) {
                @atomicStore(?*T, &@field(self.front, next), front, .Release);
                assert(@atomicRmw(usize, &self.count, .Sub, batch.count, .Monotonic) >= batch.count);
                return batch;
            }

            @atomicStore(?*T, &@field(self.front, next), null, .Monotonic);
            if (@cmpxchgStrong(?*T, &self.back, last, &self.front, .AcqRel, .Acquire) == null) {
                batch.count += 1;
                batch.last = front;
                assert(@atomicRmw(usize, &self.count, .Sub, batch.count, .Monotonic) >= batch.count);
                return batch;
            }

            next_item = @atomicLoad(?*T, &@field(front, next), .Acquire);
            while (next_item == null) : (atomic.spinLoopHint()) {
                next_item = @atomicLoad(?*T, &@field(front, next), .Acquire);
            }

            batch.count += 1;
            @atomicStore(?*T, &@field(self.front, next), next_item, .Monotonic);
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

    const Node = struct {
        next: ?*@This() = null,
        value: usize,
    };

    const Context = struct {
        gpa: *mem.Allocator,
        stack: *mpsc.UnboundedStack(Node, .next),

        pub fn runProducer(self: @This()) !void {
            var i: usize = 0;
            while (i < num_items_per_producer) : (i += 1) {
                const node = try self.gpa.create(Node);
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

    var stack: mpsc.UnboundedStack(Node, .next) = .{};

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

    try testing.expectEqual(@as(?*Node, null), stack.popBatch());
    try testing.expect(stack.isEmpty());
}

test "mpsc/unbounded_queue: push and pop" {
    if (builtin.single_threaded) return error.SkipZigTest;

    const cpu_count = try std.Thread.getCpuCount();
    if (cpu_count < 2) return error.SkipZigTest;

    const num_items_per_producer = 100_000;

    const Node = struct {
        next: ?*@This() = null,
        value: usize,
    };

    const Context = struct {
        gpa: *mem.Allocator,
        queue: *mpsc.UnboundedQueue(Node, .next),

        pub fn runProducer(self: @This()) !void {
            var i: usize = 0;
            while (i < num_items_per_producer) : (i += 1) {
                const node = try self.gpa.create(Node);
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

    var queue: mpsc.UnboundedQueue(Node, .next) = .{};

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

    try testing.expectEqual(@as(?*Node, null), queue.pop());
    try testing.expect(queue.popBatch().iterator().next() == null);
    try testing.expect(queue.popBatch().count == 0);

    try testing.expectEqual(@as(usize, 0), queue.peek());
}

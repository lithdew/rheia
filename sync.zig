const std = @import("std");

const os = std.os;
const atomic = std.atomic;
const builtin = std.builtin;
const testing = std.testing;
const runtime = @import("runtime.zig");

const Atomic = std.atomic.Atomic;

pub const Lock = struct {
    pub const locked_bit = 0b01;
    pub const queue_locked_bit: usize = 0b10;
    pub const queue_mask: usize = ~@as(usize, 0b11);

    pub const Waiter = struct {
        task: runtime.Task,
        worker_id: usize,

        queue_tail: ?*Lock.Waiter = null,
        prev: ?*Lock.Waiter = null,
        next: ?*Lock.Waiter = null,
    };

    state: Atomic(usize) = .{ .value = 0 },

    pub fn acquire(self: *Lock) void {
        if (builtin.single_threaded) return;

        if (self.tryAcquire()) {
            return;
        }
        return self.acquireSlow();
    }

    pub inline fn tryAcquire(self: *Lock) bool {
        if (builtin.single_threaded) return true;

        return self.state.tryCompareAndSwap(
            0,
            locked_bit,
            .Acquire,
            .Monotonic,
        ) == null;
    }

    fn acquireSlow(self: *Lock) void {
        @setCold(true);

        // var spin_wait: SpinWait = .{};
        var state = self.state.load(.Monotonic);
        while (true) {
            if (state & locked_bit == 0) {
                state = self.state.tryCompareAndSwap(
                    state,
                    state | locked_bit,
                    .Acquire,
                    .Monotonic,
                ) orelse {
                    return;
                };

                continue;
            }

            // if (@intToPtr(?*Lock.Waiter, state & queue_mask) == null and spin_wait.spin()) {
            //     state = self.state.load(.Monotonic);
            //     continue;
            // }

            var waiter: Lock.Waiter = .{
                .task = .{ .frame = @frame() },
                .worker_id = runtime.getCurrentWorkerId(),
            };

            suspend {
                if (@intToPtr(?*Lock.Waiter, state & queue_mask)) |head| {
                    waiter.queue_tail = null;
                    waiter.prev = null;
                    waiter.next = head;
                } else {
                    waiter.queue_tail = &waiter;
                    waiter.prev = null;
                }

                if (self.state.tryCompareAndSwap(
                    state,
                    (state & ~queue_mask) | @ptrToInt(&waiter),
                    .Release,
                    .Monotonic,
                )) |new_state| {
                    state = new_state;
                    resume @frame();
                }
            }

            // spin_wait.reset();
            state = self.state.load(.Monotonic);
        }
    }

    pub inline fn release(self: *Lock) void {
        if (builtin.single_threaded) return;

        const state = self.state.fetchSub(locked_bit, .Release);
        if (state & queue_locked_bit != 0 or @intToPtr(?*Lock.Waiter, state & queue_mask) == null) {
            return;
        }
        return self.releaseSlow();
    }

    fn releaseSlow(self: *Lock) void {
        @setCold(true);

        var state = self.state.load(.Monotonic);
        while (true) {
            if (state & queue_locked_bit != 0 or @intToPtr(?*Lock.Waiter, state & queue_mask) == null) {
                return;
            }

            state = self.state.tryCompareAndSwap(
                state,
                state | queue_locked_bit,
                .Acquire,
                .Monotonic,
            ) orelse {
                break;
            };
        }

        while (true) {
            const queue_head = @intToPtr(*Lock.Waiter, state & queue_mask);

            const queue_tail = queue_head.queue_tail orelse queue_tail: {
                var current = queue_head;
                while (true) {
                    const next = current.next orelse unreachable;
                    next.prev = current;
                    current = next;
                    if (current.queue_tail) |queue_tail| {
                        queue_head.queue_tail = queue_tail;
                        break :queue_tail queue_tail;
                    }
                }
            };

            if (state & locked_bit != 0) {
                state = self.state.tryCompareAndSwap(state, state & ~queue_locked_bit, .AcqRel, .Acquire) orelse {
                    return;
                };

                continue;
            }

            if (queue_tail.prev) |new_tail| {
                queue_head.queue_tail = new_tail;
                _ = self.state.fetchAnd(~queue_locked_bit, .Release);
            } else if (self.state.tryCompareAndSwap(state, state & locked_bit, .AcqRel, .Acquire)) |new_state| {
                state = new_state;
                continue;
            }

            break runtime.scheduleTo(queue_tail.worker_id, &queue_tail.task);
        }
    }
};

pub const SpinWait = struct {
    counter: u5 = 0,

    pub inline fn reset(self: *SpinWait) void {
        self.counter = 0;
    }

    pub inline fn spin(self: *SpinWait) bool {
        if (self.counter >= 10) return false;
        self.counter += 1;
        if (self.counter <= 3) {
            cpuRelax(@as(u32, 1) << self.counter);
        } else {
            os.sched_yield() catch {};
        }
        return true;
    }

    pub inline fn spinNoYield(self: *SpinWait) void {
        self.counter += 1;
        if (self.counter > 10) {
            self.counter = 10;
        }
        cpuRelax(@as(u32, 1) << self.counter);
    }

    inline fn cpuRelax(iterations: u32) void {
        var i: u32 = 0;
        while (i < iterations) : (i += 1) {
            atomic.spinLoopHint();
        }
    }
};

test {
    testing.refAllDecls(@This());
}

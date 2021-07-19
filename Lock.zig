const std = @import("std");

const builtin = std.builtin;
const testing = std.testing;

const Atomic = std.atomic.Atomic;

const Worker = @import("Worker.zig");
const Runtime = @import("Runtime.zig");
const SpinWait = @import("SpinWait.zig");

const Lock = @This();

pub const locked_bit = 1;
pub const queue_locked_bit: usize = 2;
pub const queue_mask: usize = ~@as(usize, 3);

pub const Waiter = struct {
    task: Worker.Task,
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
            .task = .{ .value = @frame() },
            .worker_id = Worker.getCurrent().id,
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

pub inline fn release(self: *Lock, runtime: *Runtime) void {
    if (builtin.single_threaded) return;

    const state = self.state.fetchSub(locked_bit, .Release);
    if (state & queue_locked_bit != 0 or @intToPtr(?*Lock.Waiter, state & queue_mask) == null) {
        return;
    }
    return self.releaseSlow(runtime);
}

fn releaseSlow(self: *Lock, runtime: *Runtime) void {
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

    outer: while (true) {
        const queue_head = @intToPtr(?*Lock.Waiter, state & queue_mask) orelse unreachable;

        var current = queue_head;
        const queue_tail = while (true) {
            if (current.queue_tail) |queue_tail| {
                break queue_tail;
            }

            const next = current.next orelse unreachable;
            next.prev = current;
            current = next;
        } else unreachable;

        queue_head.queue_tail = queue_tail;

        if (state & locked_bit != 0) {
            state = self.state.tryCompareAndSwap(
                state,
                state & ~queue_locked_bit,
                .Release,
                .Monotonic,
            ) orelse {
                return;
            };

            @fence(.Acquire);
            continue;
        }

        var new_tail = queue_tail.prev;
        if (new_tail) |tail| {
            queue_head.queue_tail = tail;
            _ = self.state.fetchAnd(~queue_locked_bit, .Release);
        } else while (true) {
            state = self.state.tryCompareAndSwap(state, state & locked_bit, .Release, .Monotonic) orelse {
                break;
            };

            if (@intToPtr(?*Lock.Waiter, state & queue_mask) == null) {
                continue;
            }

            @fence(.Acquire);
            continue :outer;
        }

        break runtime.scheduleTo(queue_tail.worker_id, &queue_tail.task);
    }
}

test {
    testing.refAllDecls(@This());
}

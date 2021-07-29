const std = @import("std");

const runtime = @import("runtime.zig");

const assert = std.debug.assert;

const Task = runtime.Task;
const Context = runtime.Context;
const DoublyLinkedDeque = @import("intrusive.zig").DoublyLinkedDeque;

pub fn Parker(comptime T: type) type {
    return struct {
        const Self = @This();

        pub const Waiter = struct {
            task: Task,
            result: ?T = null,
        };

        waiters: Task.Deque = .{},

        pub fn isEmpty(self: *const Self) bool {
            return self.waiters.isEmpty();
        }

        pub fn park(self: *Self, ctx: *Context) !T {
            var waiter: Self.Waiter = .{ .task = .{ .frame = @frame() } };

            var callback: struct {
                state: Context.Callback = .{ .run = @This().run },
                self: *Self,
                waiter: *Task,

                pub fn run(state: *Context.Callback) void {
                    const callback = @fieldParentPtr(@This(), "state", state);
                    if (callback.self.waiters.remove(callback.waiter)) {
                        runtime.schedule(callback.waiter);
                    }
                }
            } = .{ .self = self, .waiter = &waiter.task };

            try ctx.register(&callback.state);
            defer ctx.deregister(&callback.state);

            suspend self.waiters.append(&waiter.task);
            return waiter.result orelse return error.Cancelled;
        }

        pub fn notify(self: *Self, result: ?T) void {
            const task = self.waiters.popFirst() orelse return;
            const waiter = @fieldParentPtr(Self.Waiter, "task", task);
            waiter.result = result;
            runtime.schedule(task);
        }

        pub fn broadcast(self: *Self, result: ?T) void {
            while (self.waiters.popFirst()) |task| {
                const waiter = @fieldParentPtr(Self.Waiter, "task", task);
                waiter.result = result;
                runtime.schedule(task);
            }
        }
    };
}

pub const Mutex = struct {
    locked: bool = false,
    waiters: Task.Deque = .{},

    pub fn acquire(self: *Mutex, ctx: *Context) !void {
        var waiter: Task = .{ .frame = @frame() };

        var callback: struct {
            state: Context.Callback = .{ .run = @This().run },
            self: *Mutex,
            waiter: *Task,

            pub fn run(state: *Context.Callback) void {
                const callback = @fieldParentPtr(@This(), "state", state);
                if (callback.self.waiters.remove(callback.waiter)) {
                    if (callback.self.waiters.isEmpty()) {
                        callback.self.locked = false;
                    }
                    runtime.schedule(callback.waiter);
                }
            }
        } = .{ .self = self, .waiter = &waiter };

        try ctx.register(&callback.state);
        defer ctx.deregister(&callback.state);

        if (!self.locked) {
            self.locked = true;
            return;
        }

        suspend self.waiters.append(&waiter);
    }

    pub fn release(self: *Mutex) void {
        assert(self.locked);

        runtime.schedule(self.waiters.popFirst() orelse {
            self.locked = false;
            return;
        });
    }
};

pub const WaitGroup = struct {
    len: usize = 0,
    waiters: Task.Deque = .{},

    pub fn wait(self: *WaitGroup, ctx: *Context) !void {
        var waiter: Task = .{ .frame = @frame() };

        var callback: struct {
            state: Context.Callback = .{ .run = @This().run },
            self: *WaitGroup,
            waiter: *Task,

            pub fn run(state: *Context.Callback) void {
                const callback = @fieldParentPtr(@This(), "state", state);
                if (callback.self.waiters.remove(callback.waiter)) {
                    runtime.schedule(callback.waiter);
                }
            }
        } = .{ .self = self, .waiter = &waiter };

        try ctx.register(&callback.state);
        defer ctx.deregister(&callback.state);

        if (self.len == 0) return;

        suspend self.waiters.append(&waiter);
    }

    pub fn add(self: *WaitGroup, delta: usize) void {
        self.len += delta;
    }

    pub fn sub(self: *WaitGroup, delta: usize) void {
        self.len -= delta;
        if (self.len > 0) return;
        while (self.waiters.popFirst()) |waiter| {
            runtime.schedule(waiter);
        }
    }
};

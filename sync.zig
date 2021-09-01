const std = @import("std");
const runtime = @import("runtime.zig");

const mem = std.mem;
const meta = std.meta;
const math = std.math;
const builtin = std.builtin;

const assert = std.debug.assert;

const Task = runtime.Task;
const Context = runtime.Context;
const SinglyLinkedList = @import("intrusive.zig").SinglyLinkedList;
const DoublyLinkedDeque = @import("intrusive.zig").DoublyLinkedDeque;
const DynamicRingBuffer = @import("ring_buffer.zig").DynamicRingBuffer;

const sync = @This();

pub fn BoundedTaskPool(comptime F: anytype) type {
    return struct {
        const Self = @This();

        pub const Metadata = struct {
            next: ?*Metadata = null,

            pub fn create(gpa: *mem.Allocator) !*Metadata {
                const bytes = try gpa.alignedAlloc(
                    u8,
                    math.max(@alignOf(Metadata), @alignOf(anyframe)),
                    @sizeOf(Metadata) + @frameSize(Self.run),
                );

                return @ptrCast(*Metadata, bytes.ptr);
            }

            pub fn deinit(self: *Metadata, gpa: *mem.Allocator) void {
                const bytes = @ptrCast([*]u8, self)[0 .. @sizeOf(Metadata) + @frameSize(Self.run)];
                gpa.free(bytes);
            }

            pub fn getFrame(self: *Metadata) *@Frame(Self.run) {
                const ptr = @ptrCast([*]u8, self) + @sizeOf(Metadata);
                const frame = @ptrCast(*@Frame(Self.run), ptr);
                return frame;
            }
        };

        capacity: usize,

        wg: sync.WaitGroup = .{},
        parker: Parker(void) = .{},
        free_list: SinglyLinkedList(Metadata, .next) = .{},

        pub fn deinit(self: *Self, ctx: *Context, gpa: *mem.Allocator) !void {
            const result = self.wg.wait(ctx);
            while (self.free_list.popFirst()) |metadata| {
                metadata.deinit(gpa);
            }
            return result;
        }

        pub const SpawnError = mem.Allocator.Error || error{
            Cancelled,
        };

        pub fn spawn(self: *Self, ctx: *Context, gpa: *mem.Allocator, args: meta.ArgsTuple(@TypeOf(F))) SpawnError!void {
            _ = ctx;

            // while (self.wg.len == self.capacity) {
            //     try self.parker.park(ctx);
            // }

            const metadata = metadata: {
                if (self.free_list.popFirst()) |metadata| {
                    break :metadata metadata;
                }
                break :metadata try Metadata.create(gpa);
            };

            metadata.* = .{};
            metadata.getFrame().* = async self.run(metadata, args);
        }

        fn run(self: *Self, metadata: *Metadata, args: meta.ArgsTuple(@TypeOf(F))) callconv(.Async) void {
            self.wg.add(1);
            defer self.wg.sub(1);

            defer {
                self.free_list.prepend(metadata);
                self.parker.notify({});
            }

            if (@typeInfo(@typeInfo(@TypeOf(F)).Fn.return_type.?) == .ErrorUnion) {
                @call(.{}, F, args) catch {};
            } else {
                @call(.{}, F, args);
            }
        }
    };
}

pub fn Parker(comptime T: type) type {
    return struct {
        const Self = @This();

        pub const Waiter = struct {
            task: Task,
            result: ?T = null,
        };

        result: ?T = null,
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
                        if (builtin.is_test) {
                            resume callback.waiter.frame;
                        } else {
                            runtime.schedule(callback.waiter);
                        }
                    }
                }
            } = .{ .self = self, .waiter = &waiter.task };

            try ctx.register(&callback.state);
            defer ctx.deregister(&callback.state);

            if (self.result) |result| {
                self.result = null;
                return result;
            }

            suspend self.waiters.append(&waiter.task);
            return waiter.result orelse return error.Cancelled;
        }

        pub fn notify(self: *Self, result: ?T) void {
            const task = self.waiters.popFirst() orelse {
                if (self.result == null) {
                    self.result = result;
                }
                return;
            };
            const waiter = @fieldParentPtr(Self.Waiter, "task", task);
            waiter.result = result;
            if (builtin.is_test) {
                resume task.frame;
            } else {
                runtime.schedule(task);
            }
        }

        pub fn broadcast(self: *Self, result: ?T) void {
            while (self.waiters.popFirst()) |task| {
                const waiter = @fieldParentPtr(Self.Waiter, "task", task);
                waiter.result = result;
                if (builtin.is_test) {
                    resume task.frame;
                } else {
                    runtime.schedule(task);
                }
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
                    if (builtin.is_test) {
                        resume callback.waiter.frame;
                    } else {
                        runtime.schedule(callback.waiter);
                    }
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
        if (ctx.cancelled) return error.Cancelled;
        assert(self.locked);
    }

    pub fn release(self: *Mutex) void {
        assert(self.locked);

        const waiter = self.waiters.popFirst() orelse {
            self.locked = false;
            return;
        };

        if (builtin.is_test) {
            resume waiter.frame;
        } else {
            runtime.schedule(waiter);
        }
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
                    if (builtin.is_test) {
                        resume callback.waiter.frame;
                    } else {
                        runtime.schedule(callback.waiter);
                    }
                }
            }
        } = .{ .self = self, .waiter = &waiter };

        try ctx.register(&callback.state);
        defer ctx.deregister(&callback.state);

        if (self.len == 0) return;

        suspend self.waiters.append(&waiter);
        if (ctx.cancelled) return error.Cancelled;
    }

    pub fn add(self: *WaitGroup, delta: usize) void {
        self.len += delta;
    }

    pub fn sub(self: *WaitGroup, delta: usize) void {
        self.len -= delta;
        if (self.len > 0) return;
        while (self.waiters.popFirst()) |waiter| {
            if (builtin.is_test) {
                resume waiter.frame;
            } else {
                runtime.schedule(waiter);
            }
        }
    }
};

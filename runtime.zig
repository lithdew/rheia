const std = @import("std");
const builtin = @import("builtin");
const lockfree = @import("lockfree.zig");

const io = std.io;
const os = std.os;
const mem = std.mem;
const math = std.math;
const heap = std.heap;

const Socket = std.x.os.Socket;
const Atomic = std.atomic.Atomic;

const Pool = @import("Pool.zig");
const SinglyLinkedDeque = @import("intrusive.zig").SinglyLinkedDeque;
const DoublyLinkedDeque = @import("intrusive.zig").DoublyLinkedDeque;

const panic = std.debug.panic;
const assert = std.debug.assert;

const runtime = @This();

pub var instance: Runtime = undefined;

pub fn init() !void {
    return instance.init();
}

pub fn deinit() void {
    return instance.deinit();
}

pub fn shutdown() void {
    return instance.shutdown();
}

pub fn run() !void {
    return instance.run();
}

pub fn yield() void {
    return instance.yield();
}

pub fn schedule(task: *Task) void {
    return instance.schedule(task);
}

pub fn startCpuBoundOperation() void {
    return instance.startCpuBoundOperation();
}

pub fn endCpuBoundOperation() void {
    return instance.endCpuBoundOperation();
}

pub fn pollAdd(ctx: *Context, fd: os.fd_t, poll_mask: u32) !void {
    return instance.pollAdd(ctx, fd, poll_mask);
}

pub fn read(ctx: *Context, fd: os.fd_t, buffer: []u8, offset: u64) !usize {
    return instance.read(ctx, fd, buffer, offset);
}

pub fn recv(ctx: *Context, socket: Socket, buffer: []u8, flags: u32) !usize {
    return instance.recv(ctx, socket, buffer, flags);
}

pub fn send(ctx: *Context, socket: Socket, buffer: []const u8, flags: u32) !usize {
    return instance.send(ctx, socket, buffer, flags);
}

pub fn connect(ctx: *Context, socket: Socket, address: Socket.Address) !void {
    return instance.connect(ctx, socket, address);
}

pub fn accept(
    ctx: *Context,
    socket: Socket,
    flags: std.enums.EnumFieldStruct(Socket.InitFlags, bool, false),
) !Socket.Connection {
    return instance.accept(ctx, socket, flags);
}

pub fn timeout(ctx: *Context, params: TimeoutParams) !void {
    return instance.timeout(ctx, params);
}

pub fn waitForSignal(ctx: *Context, codes: anytype) !void {
    var set = mem.zeroes(os.sigset_t);
    inline for (codes) |code| {
        os.linux.sigaddset(&set, code);
    }

    var prev_set: os.sigset_t = undefined;
    if (os.system.sigprocmask(os.SIG.BLOCK, &set, &prev_set) != 0) {
        return error.UnableToMaskSignals;
    }
    defer if (os.system.sigprocmask(os.SIG.SETMASK, &prev_set, null) != 0) {
        @panic("failed to unmask signals");
    };

    const fd = try os.signalfd(-1, &set, os.O.CLOEXEC);
    defer os.close(fd);

    var info: os.linux.signalfd_siginfo = undefined;

    const num_bytes = try runtime.read(ctx, fd, mem.asBytes(&info), 0);
    if (num_bytes < @sizeOf(os.linux.signalfd_siginfo)) return error.ShortRead;
}

pub fn getAllocator() mem.Allocator {
    return instance.gpa;
}

pub const TimeoutParams = struct {
    seconds: i64 = 0,
    nanoseconds: i64 = 0,
    mode: enum(u32) {
        relative = 0,
        absolute = os.linux.IORING_TIMEOUT_ABS,
    } = .relative,
};

pub const Task = struct {
    pub const Deque = DoublyLinkedDeque(Task, .next, .prev);
    pub const Stack = lockfree.mpsc.UnboundedStack(Task, .next);

    next: ?*Task = null,
    prev: ?*Task = null,
    frame: anyframe,
};

pub const Context = struct {
    pub const Timeout = struct {
        ctx: Context,
        parent: *Context,
        state: Context.Callback,
        frame: @Frame(Context.Timeout.wait),

        pub fn init(self: *Context.Timeout, parent: *Context, params: TimeoutParams) void {
            self.ctx = .{};
            self.parent = parent;
            self.state = .{ .run = Context.Timeout.cancel };
            self.frame = async self.wait(params);
        }

        pub fn deinit(self: *Context.Timeout) void {
            self.ctx.cancel();
            await self.frame catch {};
        }

        fn wait(self: *Context.Timeout, params: TimeoutParams) !void {
            try runtime.timeout(&self.ctx, params);
            self.parent.cancel();
        }

        fn cancel(state: *Context.Callback) void {
            const callback = @fieldParentPtr(Context.Timeout, "state", state);
            callback.ctx.cancel();
        }
    };

    pub const Callback = struct {
        pub const Deque = DoublyLinkedDeque(Context.Callback, .next, .prev);

        next: ?*Context.Callback = null,
        prev: ?*Context.Callback = null,
        run: fn (*Context.Callback) void,
    };

    callbacks: Context.Callback.Deque = .{},
    cancelled: bool = false,

    pub fn register(self: *Context, callback: *Context.Callback) !void {
        if (self.cancelled) {
            callback.run(callback);
            return error.Cancelled;
        }
        self.callbacks.append(callback);
    }

    pub fn deregister(self: *Context, callback: *Context.Callback) void {
        _ = self.callbacks.remove(callback);
    }

    pub fn cancel(self: *Context) void {
        self.cancelled = true;

        while (self.callbacks.popFirst()) |callback| {
            callback.run(callback);
        }
    }
};

pub const Stream = struct {
    pub const Writer = io.Writer(Stream, ErrorSetOf(Stream.write), Stream.write);
    pub const Reader = io.Reader(Stream, ErrorSetOf(Stream.read), Stream.read);

    socket: Socket,
    context: *Context,

    read_flags: u32 = 0,
    write_flags: u32 = os.MSG.NOSIGNAL,

    pub fn reader(self: Stream) Stream.Reader {
        return Stream.Reader{ .context = self };
    }

    pub fn writer(self: Stream) Stream.Writer {
        return Stream.Writer{ .context = self };
    }

    fn ErrorSetOf(comptime F: anytype) type {
        return @typeInfo(@typeInfo(@TypeOf(F)).Fn.return_type.?).ErrorUnion.error_set;
    }

    fn write(self: Stream, buffer: []const u8) !usize {
        return runtime.send(self.context, self.socket, buffer, self.write_flags);
    }

    fn read(self: Stream, buffer: []u8) !usize {
        return runtime.recv(self.context, self.socket, buffer, self.read_flags);
    }
};

pub const cache_line_length = switch (builtin.cpu.arch) {
    .x86_64, .aarch64, .powerpc64 => 128,
    .arm, .mips, .mips64, .riscv64 => 32,
    .s390x => 256,
    else => 64,
};

pub const Runtime = struct {
    pub const Syscall = struct {
        pub const Deque = DoublyLinkedDeque(Syscall, .next, .prev);

        task: Task,
        prev: ?*Syscall = null,
        next: ?*Syscall = null,
        result: ?isize = null,
    };

    const log = std.log.scoped(.runtime);

    gpa_instance: heap.GeneralPurposeAllocator(.{}),
    gpa: mem.Allocator,

    pool: Pool,

    event: extern struct {
        fd: os.fd_t,
        count: u64,
        armed: Atomic(bool) align(cache_line_length),
    },

    ring: os.linux.IO_Uring,

    closing: bool,

    pending_tasks: Task.Deque,
    pending_cancellations: Syscall.Deque,

    incoming_tasks: Task.Stack,
    outgoing_tasks: Pool.Batch,

    pub fn init(self: *Runtime) !void {
        // defer log.debug("runtime started", .{});

        self.gpa_instance = .{};
        if (builtin.link_libc) {
            self.gpa_instance.backing_allocator = std.heap.c_allocator;
        }
        if (builtin.mode != .Debug) {
            self.gpa = &self.gpa_instance.allocator;
        } else {
            self.gpa = std.heap.c_allocator;
        }

        self.pool = Pool.init(.{ .max_threads = 7 });
        errdefer self.pool.deinit();

        self.event = .{
            .fd = try os.eventfd(0, os.O.CLOEXEC),
            .count = math.maxInt(u64),
            .armed = .{ .value = false },
        };

        errdefer os.close(self.event.fd);

        self.ring = try os.linux.IO_Uring.init(512, 0);
        errdefer self.ring.deinit();

        self.closing = false;

        self.pending_tasks = .{};
        self.pending_cancellations = .{};

        self.incoming_tasks = .{};
        self.outgoing_tasks = .{};
    }

    pub fn deinit(self: *Runtime) void {
        // defer log.debug("runtime freed", .{});

        self.ring.deinit();
        os.close(self.event.fd);

        self.pool.shutdown();
        self.pool.deinit();

        assert(!self.gpa_instance.deinit());
    }

    pub fn shutdown(self: *Runtime) void {
        self.closing = true;
    }

    pub fn yield(self: *Runtime) void {
        var task: Task = .{ .frame = @frame() };
        suspend self.schedule(&task);
    }

    pub fn schedule(self: *Runtime, task: *Task) void {
        self.pending_tasks.append(task);
    }

    pub fn notify(self: *Runtime) void {
        if (self.event.armed.compareAndSwap(true, false, .AcqRel, .Acquire) != null) {
            return;
        }
        const bytes_written = os.write(self.event.fd, mem.asBytes(&@as(u64, 1))) catch 0;
        assert(bytes_written == @sizeOf(u64));
    }

    pub fn startCpuBoundOperation(self: *Runtime) void {
        var callback: struct {
            state: Pool.Task = .{ .callback = @This().run },
            frame: anyframe,

            fn run(state: *Pool.Task) void {
                const callback = @fieldParentPtr(@This(), "state", state);
                resume callback.frame;
            }
        } = .{ .frame = @frame() };

        suspend self.outgoing_tasks.push(Pool.Batch.from(&callback.state));
    }

    pub fn endCpuBoundOperation(self: *Runtime) void {
        var task: Task = .{ .frame = @frame() };
        suspend {
            self.incoming_tasks.push(&task);
            self.notify();
        }
    }

    fn rearm(self: *Runtime) bool {
        if (self.event.armed.load(.Acquire) or self.event.count == 0) {
            return false;
        }
        if ((self.ring.read(0, self.event.fd, mem.asBytes(&self.event.count), 0) catch null) == null) {
            return true; // return true so that the next call to rearm will attempt to re-submit a read()
        }
        self.event.count = 0;
        self.event.armed.store(true, .Release);
        return true;
    }

    pub fn run(self: *Runtime) !void {
        log.debug("event loop started", .{});
        defer log.debug("event loop stopped", .{});

        var completions: [512]os.linux.io_uring_cqe = undefined;

        while (true) {
            self.pool.schedule(self.outgoing_tasks);
            self.outgoing_tasks = .{};

            while (self.incoming_tasks.pop()) |task| {
                self.pending_tasks.append(task);
            }

            var pending_cancellations: Syscall.Deque = .{};
            while (self.pending_cancellations.popFirst()) |syscall| {
                _ = ring_cancel(&self.ring, 0, @ptrToInt(syscall), 0) catch {
                    pending_cancellations.append(syscall);
                };
            }
            self.pending_cancellations = pending_cancellations;

            var tasks_resumed: usize = 0;
            while (self.pending_tasks.popFirst()) |task| : (tasks_resumed += 1) {
                resume task.frame;
            }

            if (tasks_resumed == 0 and self.closing) {
                break;
            }

            _ = self.ring.submit_and_wait(num_waiters: {
                if (self.rearm() or tasks_resumed > 0) {
                    break :num_waiters 0;
                }
                break :num_waiters 1;
            }) catch |err| switch (err) {
                error.CompletionQueueOvercommitted, error.SystemResources => 0,
                error.SignalInterrupt => continue,
                else => return err,
            };

            const num_completions = try self.ring.copy_cqes(&completions, 0);
            for (completions[0..num_completions]) |completion| {
                if (completion.user_data == 0) continue;
                const syscall = @intToPtr(*Syscall, completion.user_data);
                syscall.result = completion.res;
                self.pending_tasks.append(&syscall.task);
            }
        }
    }

    pub fn accept(
        self: *Runtime,
        ctx: *Context,
        socket: Socket,
        flags: std.enums.EnumFieldStruct(Socket.InitFlags, bool, false),
    ) !Socket.Connection {
        var syscall: Syscall = .{ .task = .{ .frame = @frame() } };
        defer _ = self.pending_cancellations.remove(&syscall);

        var callback: struct {
            state: Context.Callback = .{ .run = @This().run },

            self: *Runtime,
            syscall: *Syscall,

            pub fn run(state: *Context.Callback) void {
                const callback = @fieldParentPtr(@This(), "state", state);
                return callback.self.cancel(callback.syscall);
            }
        } = .{ .self = self, .syscall = &syscall };

        try ctx.register(&callback.state);
        defer ctx.deregister(&callback.state);

        var address: Socket.Address.Native.Storage = undefined;
        var address_len: u32 = @sizeOf(Socket.Address.Native.Storage);
        var raw_flags: u32 = 0;

        const set = std.EnumSet(Socket.InitFlags).init(flags);
        if (set.contains(.close_on_exec)) raw_flags |= os.SOCK.CLOEXEC;
        if (set.contains(.nonblocking)) raw_flags |= os.SOCK.NONBLOCK;

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = maybe_err: {
                    _ = self.ring.accept(
                        @ptrToInt(&syscall),
                        socket.fd,
                        @ptrCast(*os.sockaddr, &address),
                        &address_len,
                        raw_flags,
                    ) catch |err| {
                        self.pending_tasks.append(&syscall.task);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :maybe_err err,
                        }
                    };
                    break :maybe_err null;
                };
            }

            if (maybe_err) |err| return err;

            const result = syscall.result orelse continue;
            if (result < 0) {
                return switch (@intToEnum(os.E, -result)) {
                    .INTR => continue,
                    .AGAIN => error.WouldBlock,
                    .BADF => unreachable,
                    .CONNABORTED => error.ConnectionAborted,
                    .FAULT => unreachable,
                    .INVAL => error.SocketNotListening,
                    .NOTSOCK => unreachable,
                    .MFILE => error.ProcessFdQuotaExceeded,
                    .NFILE => error.SystemFdQuotaExceeded,
                    .NOBUFS => error.SystemResources,
                    .NOMEM => error.SystemResources,
                    .OPNOTSUPP => unreachable,
                    .PROTO => error.ProtocolFailure,
                    .PERM => error.BlockedByFirewall,
                    .CANCELED => error.Cancelled,
                    else => |err| return os.unexpectedErrno(err),
                };
            }

            const incoming = Socket{ .fd = @intCast(os.socket_t, result) };
            const incoming_address = Socket.Address.fromNative(@ptrCast(*os.sockaddr, &address));

            return Socket.Connection.from(incoming, incoming_address);
        }
    }

    pub fn recv(self: *Runtime, ctx: *Context, socket: Socket, buffer: []u8, flags: u32) !usize {
        var syscall: Syscall = .{ .task = .{ .frame = @frame() } };
        defer _ = self.pending_cancellations.remove(&syscall);

        var callback: struct {
            state: Context.Callback = .{ .run = @This().run },

            self: *Runtime,
            syscall: *Syscall,

            pub fn run(state: *Context.Callback) void {
                const callback = @fieldParentPtr(@This(), "state", state);
                return callback.self.cancel(callback.syscall);
            }
        } = .{ .self = self, .syscall = &syscall };

        try ctx.register(&callback.state);
        defer ctx.deregister(&callback.state);

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = maybe_err: {
                    _ = self.ring.recv(@ptrToInt(&syscall), socket.fd, buffer, flags) catch |err| {
                        self.pending_tasks.append(&syscall.task);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :maybe_err err,
                        }
                    };
                    break :maybe_err null;
                };
            }

            if (maybe_err) |err| return err;

            const result = syscall.result orelse continue;
            if (result < 0) {
                return switch (@intToEnum(os.E, -result)) {
                    .BADF => unreachable,
                    .FAULT => unreachable,
                    .INVAL => unreachable,
                    .NOTCONN => error.SocketNotConnected,
                    .NOTSOCK => unreachable,
                    .INTR => continue,
                    .AGAIN => error.WouldBlock,
                    .NOMEM => error.SystemResources,
                    .CONNREFUSED => error.ConnectionRefused,
                    .CONNRESET => error.ConnectionResetByPeer,
                    .CANCELED => error.Cancelled,
                    else => |err| os.unexpectedErrno(err),
                };
            }
            return @intCast(usize, result);
        }
    }

    pub fn send(self: *Runtime, ctx: *Context, socket: Socket, buffer: []const u8, flags: u32) !usize {
        var syscall: Syscall = .{ .task = .{ .frame = @frame() } };
        defer _ = self.pending_cancellations.remove(&syscall);

        var callback: struct {
            state: Context.Callback = .{ .run = @This().run },

            self: *Runtime,
            syscall: *Syscall,

            pub fn run(state: *Context.Callback) void {
                const callback = @fieldParentPtr(@This(), "state", state);
                return callback.self.cancel(callback.syscall);
            }
        } = .{ .self = self, .syscall = &syscall };

        try ctx.register(&callback.state);
        defer ctx.deregister(&callback.state);

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = maybe_err: {
                    _ = self.ring.send(@ptrToInt(&syscall), socket.fd, buffer, flags) catch |err| {
                        self.pending_tasks.append(&syscall.task);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :maybe_err err,
                        }
                    };
                    break :maybe_err null;
                };
            }

            if (maybe_err) |err| return err;

            const result = syscall.result orelse continue;
            if (result < 0) {
                return switch (@intToEnum(os.E, -result)) {
                    .ACCES => error.AccessDenied,
                    .AGAIN => error.WouldBlock,
                    .ALREADY => error.FastOpenAlreadyInProgress,
                    .BADF => unreachable,
                    .CONNRESET => error.ConnectionResetByPeer,
                    .DESTADDRREQ => unreachable,
                    .FAULT => unreachable,
                    .INTR => continue,
                    .INVAL => unreachable,
                    .ISCONN => unreachable,
                    .MSGSIZE => error.MessageTooBig,
                    .NOBUFS => error.SystemResources,
                    .NOMEM => error.SystemResources,
                    .NOTSOCK => unreachable,
                    .OPNOTSUPP => unreachable,
                    .PIPE => error.BrokenPipe,
                    .AFNOSUPPORT => error.AddressFamilyNotSupported,
                    .LOOP => error.SymLinkLoop,
                    .NAMETOOLONG => error.NameTooLong,
                    .NOENT => error.FileNotFound,
                    .NOTDIR => error.NotDir,
                    .HOSTUNREACH => error.NetworkUnreachable,
                    .NETUNREACH => error.NetworkUnreachable,
                    .NOTCONN => error.SocketNotConnected,
                    .NETDOWN => error.NetworkSubsystemFailed,
                    .CANCELED => error.Cancelled,
                    else => |err| os.unexpectedErrno(err),
                };
            }
            return @intCast(usize, result);
        }
    }

    pub fn connect(self: *Runtime, ctx: *Context, socket: Socket, address: Socket.Address) !void {
        var syscall: Syscall = .{ .task = .{ .frame = @frame() } };
        defer _ = self.pending_cancellations.remove(&syscall);

        var callback: struct {
            state: Context.Callback = .{ .run = @This().run },

            self: *Runtime,
            syscall: *Syscall,

            pub fn run(state: *Context.Callback) void {
                const callback = @fieldParentPtr(@This(), "state", state);
                return callback.self.cancel(callback.syscall);
            }
        } = .{ .self = self, .syscall = &syscall };

        try ctx.register(&callback.state);
        defer ctx.deregister(&callback.state);

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = maybe_err: {
                    _ = self.ring.connect(
                        @ptrToInt(&syscall),
                        socket.fd,
                        @ptrCast(*const os.sockaddr, &address.toNative()),
                        address.getNativeSize(),
                    ) catch |err| {
                        self.pending_tasks.append(&syscall.task);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :maybe_err err,
                        }
                    };
                    break :maybe_err null;
                };
            }

            if (maybe_err) |err| return err;

            const result = syscall.result orelse continue;
            if (result < 0) {
                return switch (@intToEnum(os.E, -result)) {
                    .ACCES => error.PermissionDenied,
                    .PERM => error.PermissionDenied,
                    .ADDRINUSE => error.AddressInUse,
                    .ADDRNOTAVAIL => error.AddressNotAvailable,
                    .AFNOSUPPORT => error.AddressFamilyNotSupported,
                    .AGAIN, .INPROGRESS => error.WouldBlock,
                    .ALREADY => error.ConnectionPending,
                    .BADF => unreachable,
                    .CONNREFUSED => error.ConnectionRefused,
                    .CONNRESET => error.ConnectionResetByPeer,
                    .FAULT => unreachable,
                    .INTR => continue,
                    .ISCONN => unreachable,
                    .NETUNREACH => error.NetworkUnreachable,
                    .NOTSOCK => unreachable,
                    .PROTOTYPE => unreachable,
                    .TIMEDOUT => error.ConnectionTimedOut,
                    .NOENT => error.FileNotFound,
                    .CANCELED => error.Cancelled,
                    else => |err| os.unexpectedErrno(err),
                };
            }
            return;
        }
    }

    pub fn pollAdd(self: *Runtime, ctx: *Context, fd: os.fd_t, poll_mask: u32) !void {
        var syscall: Syscall = .{ .task = .{ .frame = @frame() } };
        defer _ = self.pending_cancellations.remove(&syscall);

        var callback: struct {
            state: Context.Callback = .{ .run = @This().run },

            self: *Runtime,
            syscall: *Syscall,

            pub fn run(state: *Context.Callback) void {
                const callback = @fieldParentPtr(@This(), "state", state);
                return callback.self.cancel(callback.syscall);
            }
        } = .{ .self = self, .syscall = &syscall };

        try ctx.register(&callback.state);
        defer ctx.deregister(&callback.state);

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = maybe_err: {
                    _ = self.ring.poll_add(@ptrToInt(&syscall), fd, poll_mask) catch |err| {
                        self.pending_tasks.append(&syscall.task);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :maybe_err err,
                        }
                    };
                    break :maybe_err null;
                };
            }

            if (maybe_err) |err| return err;

            const result = syscall.result orelse continue;
            if (result < 0) {
                return switch (@intToEnum(os.E, -result)) {
                    .BADF => unreachable,
                    .FAULT => unreachable,
                    .INVAL => unreachable,
                    .INTR => continue,
                    .NOMEM => error.SystemResources,
                    .CANCELED => error.Cancelled,
                    else => |err| os.unexpectedErrno(err),
                };
            }
            return;
        }
    }

    pub fn read(self: *Runtime, ctx: *Context, fd: os.fd_t, buffer: []u8, offset: u64) !usize {
        var syscall: Syscall = .{ .task = .{ .frame = @frame() } };
        defer _ = self.pending_cancellations.remove(&syscall);

        var callback: struct {
            state: Context.Callback = .{ .run = @This().run },

            self: *Runtime,
            syscall: *Syscall,

            pub fn run(state: *Context.Callback) void {
                const callback = @fieldParentPtr(@This(), "state", state);
                return callback.self.cancel(callback.syscall);
            }
        } = .{ .self = self, .syscall = &syscall };

        try ctx.register(&callback.state);
        defer ctx.deregister(&callback.state);

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = maybe_err: {
                    _ = self.ring.read(@ptrToInt(&syscall), fd, buffer, offset) catch |err| {
                        self.pending_tasks.append(&syscall.task);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :maybe_err err,
                        }
                    };
                    break :maybe_err null;
                };
            }

            if (maybe_err) |err| return err;

            const result = syscall.result orelse continue;
            if (result < 0) {
                return switch (@intToEnum(os.E, -result)) {
                    .BADF => unreachable,
                    .FAULT => unreachable,
                    .INVAL => unreachable,
                    .NOTCONN => error.SocketNotConnected,
                    .NOTSOCK => unreachable,
                    .INTR => continue,
                    .AGAIN => error.WouldBlock,
                    .NOMEM => error.SystemResources,
                    .CONNREFUSED => error.ConnectionRefused,
                    .CONNRESET => error.ConnectionResetByPeer,
                    .CANCELED => error.Cancelled,
                    else => |err| os.unexpectedErrno(err),
                };
            }
            return @intCast(usize, result);
        }
    }

    pub fn timeout(self: *Runtime, ctx: *Context, params: TimeoutParams) !void {
        var syscall: Syscall = .{ .task = .{ .frame = @frame() } };
        defer _ = self.pending_cancellations.remove(&syscall);

        var callback: struct {
            state: Context.Callback = .{ .run = @This().run },

            self: *Runtime,
            syscall: *Syscall,

            pub fn run(state: *Context.Callback) void {
                const callback = @fieldParentPtr(@This(), "state", state);
                return callback.self.cancel(callback.syscall);
            }
        } = .{ .self = self, .syscall = &syscall };

        try ctx.register(&callback.state);
        defer ctx.deregister(&callback.state);

        if (params.seconds == 0 and params.nanoseconds == 0) {
            return;
        }

        const timespec: os.linux.kernel_timespec = .{
            .tv_sec = params.seconds,
            .tv_nsec = params.nanoseconds,
        };

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = maybe_err: {
                    _ = self.ring.timeout(@ptrToInt(&syscall), &timespec, 0, @enumToInt(params.mode)) catch |err| {
                        self.pending_tasks.append(&syscall.task);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :maybe_err err,
                        }
                    };
                    break :maybe_err null;
                };
            }

            if (maybe_err) |err| return err;

            const result = syscall.result orelse continue;
            if (result < 0) {
                return switch (@intToEnum(os.E, -result)) {
                    .TIME => {},
                    .CANCELED => error.Cancelled,
                    else => |err| os.unexpectedErrno(err),
                };
            }
            return;
        }
    }

    fn cancel(self: *Runtime, target_syscall: *Syscall) void {
        self.pending_cancellations.append(target_syscall);
    }
};

fn ring_cancel(self: *os.linux.IO_Uring, user_data: u64, target_user_data: u64, flags: u32) !*os.linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    io_uring_prep_cancel(sqe, target_user_data, flags);
    sqe.user_data = user_data;
    return sqe;
}

fn io_uring_prep_cancel(sqe: *os.linux.io_uring_sqe, user_data: u64, flags: u32) void {
    os.linux.io_uring_prep_rw(.ASYNC_CANCEL, sqe, -1, user_data, 0, 0);
    sqe.rw_flags = flags;
}

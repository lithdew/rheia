const std = @import("std");

const os = std.os;
const ip = std.x.net.ip;

const mem = std.mem;
const testing = std.testing;

const spsc = @import("spsc.zig");

const assert = std.debug.assert;

const Socket = std.x.os.Socket;
const Atomic = std.atomic.Atomic;

const Ring = os.linux.IO_Uring;
const Submission = os.linux.io_uring_sqe;
const Completion = os.linux.io_uring_cqe;
const RingParams = os.linux.io_uring_params;

pub const Worker = struct {
    pub const TaskQueue = spsc.UnboundedQueue(*Worker.Task);

    pub const Task = struct {
        runFn: fn (*Task) void,
    };

    const log = std.log.scoped(.io_worker);

    id: usize,
    loop: Loop,
    task_queues: std.ArrayListUnmanaged(TaskQueue) = .{},

    shutdown_requested: Atomic(bool) = .{ .value = false },

    pub fn init(self: *Worker, gpa: *mem.Allocator, count: usize, id: usize) !void {
        var loop: Loop = undefined;
        try loop.init(null);
        errdefer loop.deinit();

        var task_queues = try std.ArrayListUnmanaged(TaskQueue).initCapacity(gpa, count);
        errdefer task_queues.deinit(gpa);

        var task_queue_index: usize = 0;
        errdefer for (task_queues.items[0..task_queue_index]) |*task_queue| task_queue.deinit(gpa);

        while (task_queue_index < count) : (task_queue_index += 1) {
            task_queues.addOneAssumeCapacity().* = try TaskQueue.init(gpa);
        }

        self.* = .{
            .id = id,
            .loop = loop,
            .task_queues = task_queues,
        };
    }

    pub fn deinit(self: *Worker, gpa: *mem.Allocator) void {
        self.loop.deinit();
        for (self.task_queues.items) |*task_queue| {
            task_queue.deinit(gpa);
        }
        self.task_queues.deinit(gpa);
    }

    pub fn shutdown(self: *Worker) void {
        self.shutdown_requested.store(true, .Release);
        self.loop.notify();
    }

    pub fn pollTaskQueues(self: *Worker) usize {
        var attempts: usize = 0;
        var num_tasks_processed: usize = 0;

        while (attempts < 128) : (attempts += 1) {
            var num_tasks_processed_in_attempt: usize = 0;

            for (self.task_queues.items) |*task_queue| {
                const task = task_queue.pop() orelse continue;
                num_tasks_processed_in_attempt += 1;
                task.runFn(task);
            }

            if (num_tasks_processed_in_attempt == 0) break;
            num_tasks_processed += num_tasks_processed_in_attempt;
        }

        return num_tasks_processed;
    }

    pub fn run(self: *Worker) !void {
        log.debug("worker {} started", .{self.id});
        defer log.debug("worker {} is done", .{self.id});

        while (true) {
            const num_tasks_processed = self.pollTaskQueues();
            try self.loop.poll(if (num_tasks_processed > 0) .nonblocking else .blocking);
            if (self.shutdown_requested.load(.Acquire) and self.loop.pending == 0) {
                break;
            }
        }
    }
};

pub const Loop = struct {
    pub const Waiter = struct {
        node: std.TailQueue(void).Node = undefined,
        result: ?isize = null,
        frame: anyframe,
    };

    pub const Timer = struct {
        pub const Params = struct {
            seconds: i64 = 0,
            nanoseconds: i64 = 0,
            mode: enum(u32) {
                relative = 0,
                absolute = os.IORING_TIMEOUT_ABS,
            } = .relative,
        };

        loop: *Loop,
        waiter: Loop.Waiter,
        frame: @Frame(Loop.Timer.handle),

        pub fn init(loop: *Loop) Loop.Timer {
            return .{ .loop = loop, .waiter = undefined, .frame = undefined };
        }

        pub fn start(self: *Loop.Timer, params: Loop.Timer.Params) void {
            self.frame = async self.handle(params);
        }

        pub fn wait(self: *Loop.Timer) !void {
            return await self.frame catch |err| switch (err) {
                error.Timeout => {},
                else => err,
            };
        }

        pub fn waitFor(self: *Loop.Timer, params: Loop.Timer.Params) !void {
            self.start(params);
            return self.wait();
        }

        pub fn cancel(self: *Loop.Timer) !void {
            var waiter: Loop.Waiter = .{ .frame = @frame() };

            while (true) {
                var maybe_err: ?anyerror = null;

                suspend {
                    maybe_err = blk: {
                        _ = self.loop.ring.timeout_remove(@ptrToInt(&waiter.node), @ptrToInt(&self.waiter.node), 0) catch |err| {
                            self.loop.submissions.append(&waiter.node);
                            switch (err) {
                                error.SubmissionQueueFull => {},
                                else => break :blk err,
                            }
                        };
                        break :blk null;
                    };
                }
                if (maybe_err) |err| return err;

                const result = waiter.result orelse continue;
                return switch (-result) {
                    0 => {},
                    os.EBUSY => error.TimeoutAlreadyCancelled,
                    os.ENOENT => error.TimeoutNotFound,
                };
            }
        }

        fn handle(self: *Loop.Timer, params: Loop.Timer.Params) !void {
            const timespec: os.__kernel_timespec = .{ .tv_sec = params.seconds, .tv_nsec = params.nanoseconds };

            self.waiter = .{ .frame = @frame() };

            while (true) {
                var maybe_err: ?anyerror = null;

                suspend {
                    maybe_err = blk: {
                        _ = self.loop.ring.timeout(@ptrToInt(&self.waiter.node), &timespec, 0, @enumToInt(params.mode)) catch |err| {
                            self.loop.submissions.append(&self.waiter.node);
                            switch (err) {
                                error.SubmissionQueueFull => {},
                                else => break :blk err,
                            }
                        };
                        break :blk null;
                    };
                }
                if (maybe_err) |err| return err;

                const result = self.waiter.result orelse continue;
                return switch (-result) {
                    0 => {},
                    os.ETIME => error.Timeout,
                    os.ECANCELED => error.TimeoutCancelled,
                    else => |err| os.unexpectedErrno(err),
                };
            }
        }
    };

    ring: Ring,

    notifier: struct {
        rearm_required: bool = true,
        buffer: u64 = undefined,
        fd: os.fd_t,
    },

    submissions: std.TailQueue(void) = .{},
    completions: std.TailQueue(void) = .{},
    pending: usize = 0,

    pub fn init(self: *Loop, maybe_params: ?*RingParams) !void {
        var ring = try if (maybe_params) |params| Ring.init_params(256, params) else Ring.init(256, 0);
        errdefer ring.deinit();

        const notifier_fd = try os.eventfd(0, os.O_CLOEXEC);
        errdefer os.close(notifier_fd);

        self.* = .{ .ring = ring, .notifier = .{ .fd = notifier_fd } };
    }

    pub fn deinit(self: *Loop) void {
        self.ring.deinit();
    }

    pub fn notify(self: *Loop) void {
        const bytes_written = os.write(self.notifier.fd, mem.asBytes(&@as(u64, 1))) catch unreachable;
        assert(bytes_written == @sizeOf(u64));
    }

    pub fn reset(self: *Loop) void {
        _ = self.ring.read(0, self.notifier.fd, mem.asBytes(&self.notifier.buffer), 0) catch {};
    }

    pub fn poll(self: *Loop, method: enum(u32) { blocking = 1, nonblocking = 0 }) !void {
        var completions: [256]Completion = undefined;

        self.pending += self.ring.submit_and_wait(wait_count: {
            if (self.submissions.len > 0 or self.completions.len > 0) {
                break :wait_count 0;
            }
            if (self.notifier.rearm_required) {
                self.notifier.rearm_required = false;
                self.reset();
            }
            break :wait_count @enumToInt(method);
        }) catch |err| switch (err) {
            error.CompletionQueueOvercommitted, error.SystemResources => 0,
            error.SignalInterrupt => return,
            else => return err,
        };

        const completion_count = try self.ring.copy_cqes(&completions, 0);
        for (completions[0..completion_count]) |completion| {
            if (completion.user_data == 0) {
                self.notifier.rearm_required = true;
                self.pending -= 1;
                continue;
            }

            const waiter = @intToPtr(*Waiter, completion.user_data);
            waiter.result = completion.res;

            self.completions.append(&waiter.node);
        }

        var it: std.TailQueue(void) = .{};
        mem.swap(std.TailQueue(void), &it, &self.submissions);
        const num_submissions = it.len;
        while (it.popFirst()) |node| {
            const waiter = @fieldParentPtr(Waiter, "node", node);
            resume waiter.frame;
        }
        if (num_submissions > 0) return;

        mem.swap(std.TailQueue(void), &it, &self.completions);
        const num_completions = it.len;
        while (it.popFirst()) |node| {
            const waiter = @fieldParentPtr(Waiter, "node", node);
            resume waiter.frame;
        }
        self.pending -= num_completions;
    }

    pub fn read(self: *Loop, fd: os.fd_t, buffer: []u8, offset: u64) !usize {
        var waiter: Loop.Waiter = .{ .frame = @frame() };

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = blk: {
                    _ = self.ring.read(@ptrToInt(&waiter), fd, buffer, offset) catch |err| {
                        self.submissions.append(&waiter.node);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :blk err,
                        }
                    };
                    break :blk null;
                };
            }
            if (maybe_err) |err| return err;

            const result = waiter.result orelse continue;
            if (result < 0) {
                return switch (-result) {
                    os.EBADF => unreachable,
                    os.EFAULT => unreachable,
                    os.EINVAL => unreachable,
                    os.ENOTCONN => unreachable,
                    os.ENOTSOCK => unreachable,
                    os.EINTR => continue,
                    os.EAGAIN => error.WouldBlock,
                    os.ENOMEM => error.SystemResources,
                    os.ECONNREFUSED => error.ConnectionRefused,
                    os.ECONNRESET => error.ConnectionResetByPeer,
                    else => |err| os.unexpectedErrno(err),
                };
            }
            return @intCast(usize, result);
        }
    }

    pub fn write(self: *Loop, fd: os.fd_t, buffer: []const u8, offset: u64) !usize {
        var waiter: Loop.Waiter = .{ .frame = @frame() };

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = blk: {
                    _ = self.ring.write(@ptrToInt(&waiter), fd, buffer, offset) catch |err| {
                        self.submissions.append(&waiter.node);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :blk err,
                        }
                    };
                    break :blk null;
                };
            }

            const result = waiter.result orelse continue;
            if (result < 0) {
                return switch (-result) {
                    os.EINTR => continue,
                    os.EINVAL => unreachable,
                    os.EFAULT => unreachable,
                    os.EAGAIN => return error.WouldBlock,
                    os.EBADF => return error.NotOpenForWriting, // can be a race condition.
                    os.EDESTADDRREQ => unreachable, // `connect` was never called.
                    os.EDQUOT => return error.DiskQuota,
                    os.EFBIG => return error.FileTooBig,
                    os.EIO => return error.InputOutput,
                    os.ENOSPC => return error.NoSpaceLeft,
                    os.EPERM => return error.AccessDenied,
                    os.EPIPE => return error.BrokenPipe,
                    os.ECONNRESET => return error.ConnectionResetByPeer,
                    else => |err| return os.unexpectedErrno(err),
                };
            }
            return @intCast(usize, result);
        }
    }

    pub fn recv(self: *Loop, fd: os.socket_t, buffer: []u8, flags: u32) !usize {
        var waiter: Loop.Waiter = .{ .frame = @frame() };

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = blk: {
                    _ = self.ring.recv(@ptrToInt(&waiter), fd, buffer, flags) catch |err| {
                        self.submissions.append(&waiter.node);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :blk err,
                        }
                    };
                    break :blk null;
                };
            }

            if (maybe_err) |err| return err;

            const result = waiter.result orelse continue;
            if (result < 0) {
                return switch (-result) {
                    os.EBADF => unreachable,
                    os.EFAULT => unreachable,
                    os.EINVAL => unreachable,
                    os.ENOTCONN => unreachable,
                    os.ENOTSOCK => unreachable,
                    os.EINTR => continue,
                    os.EAGAIN => error.WouldBlock,
                    os.ENOMEM => error.SystemResources,
                    os.ECONNREFUSED => error.ConnectionRefused,
                    os.ECONNRESET => error.ConnectionResetByPeer,
                    else => |err| os.unexpectedErrno(err),
                };
            }
            return @intCast(usize, result);
        }
    }

    pub fn send(self: *Loop, fd: os.socket_t, buffer: []const u8, flags: u32) !usize {
        var waiter: Loop.Waiter = .{ .frame = @frame() };

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = blk: {
                    _ = self.ring.send(@ptrToInt(&waiter), fd, buffer, flags) catch |err| {
                        self.submissions.append(&waiter.node);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :blk err,
                        }
                    };
                    break :blk null;
                };
            }

            if (maybe_err) |err| return err;

            const result = waiter.result orelse continue;
            if (result < 0) {
                return switch (-result) {
                    os.EACCES => error.AccessDenied,
                    os.EAGAIN => error.WouldBlock,
                    os.EALREADY => error.FastOpenAlreadyInProgress,
                    os.EBADF => unreachable, // always a race condition
                    os.ECONNRESET => error.ConnectionResetByPeer,
                    os.EDESTADDRREQ => unreachable, // The socket is not connection-mode, and no peer address is set.
                    os.EFAULT => unreachable, // An invalid user space address was specified for an argument.
                    os.EINTR => continue,
                    os.EINVAL => unreachable, // Invalid argument passed.
                    os.EISCONN => unreachable, // connection-mode socket was connected already but a recipient was specified
                    os.EMSGSIZE => error.MessageTooBig,
                    os.ENOBUFS => error.SystemResources,
                    os.ENOMEM => error.SystemResources,
                    os.ENOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
                    os.EOPNOTSUPP => unreachable, // Some bit in the flags argument is inappropriate for the socket type.
                    os.EPIPE => error.BrokenPipe,
                    os.EAFNOSUPPORT => error.AddressFamilyNotSupported,
                    os.ELOOP => error.SymLinkLoop,
                    os.ENAMETOOLONG => error.NameTooLong,
                    os.ENOENT => error.FileNotFound,
                    os.ENOTDIR => error.NotDir,
                    os.EHOSTUNREACH => error.NetworkUnreachable,
                    os.ENETUNREACH => error.NetworkUnreachable,
                    os.ENOTCONN => error.SocketNotConnected,
                    os.ENETDOWN => error.NetworkSubsystemFailed,
                    else => |err| os.unexpectedErrno(err),
                };
            }
            return @intCast(usize, result);
        }
    }

    pub fn connect(self: *Loop, fd: os.socket_t, address: Socket.Address) !void {
        var waiter: Loop.Waiter = .{ .frame = @frame() };

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = blk: {
                    _ = self.ring.connect(@ptrToInt(&waiter), fd, @ptrCast(*const os.sockaddr, &address.toNative()), address.getNativeSize()) catch |err| {
                        self.submissions.append(&waiter.node);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :blk err,
                        }
                    };
                    break :blk null;
                };
            }

            if (maybe_err) |err| return err;

            const result = waiter.result orelse continue;
            if (result < 0) {
                return switch (-result) {
                    os.EACCES => error.PermissionDenied,
                    os.EPERM => error.PermissionDenied,
                    os.EADDRINUSE => error.AddressInUse,
                    os.EADDRNOTAVAIL => error.AddressNotAvailable,
                    os.EAFNOSUPPORT => error.AddressFamilyNotSupported,
                    os.EAGAIN, os.EINPROGRESS => error.WouldBlock,
                    os.EALREADY => error.ConnectionPending,
                    os.EBADF => unreachable, // sockfd is not a valid open file descriptor.
                    os.ECONNREFUSED => error.ConnectionRefused,
                    os.ECONNRESET => error.ConnectionResetByPeer,
                    os.EFAULT => unreachable, // The socket structure address is outside the user's address space.
                    os.EINTR => continue,
                    os.EISCONN => unreachable, // The socket is already connected.
                    os.ENETUNREACH => error.NetworkUnreachable,
                    os.ENOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
                    os.EPROTOTYPE => unreachable, // The socket type does not support the requested communications protocol.
                    os.ETIMEDOUT => error.ConnectionTimedOut,
                    os.ENOENT => error.FileNotFound, // Returned when socket is AF_UNIX and the given path does not exist.
                    else => |err| os.unexpectedErrno(err),
                };
            }

            return;
        }
    }

    pub fn accept(self: *Loop, fd: os.socket_t, flags: std.enums.EnumFieldStruct(Socket.InitFlags, bool, false)) !Socket.Connection {
        const set = std.EnumSet(Socket.InitFlags).init(flags);

        var address: Socket.Address.Native.Storage = undefined;
        var address_len: u32 = @sizeOf(Socket.Address.Native.Storage);

        var raw_flags: u32 = 0;
        if (set.contains(.close_on_exec)) raw_flags |= os.SOCK_CLOEXEC;
        if (set.contains(.nonblocking)) raw_flags |= os.SOCK_NONBLOCK;

        var waiter: Loop.Waiter = .{ .frame = @frame() };

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = blk: {
                    _ = self.ring.accept(@ptrToInt(&waiter), fd, @ptrCast(*os.sockaddr, &address), &address_len, raw_flags) catch |err| {
                        self.submissions.append(&waiter.node);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :blk err,
                        }
                    };
                    break :blk null;
                };
            }

            if (maybe_err) |err| return err;

            const result = waiter.result orelse continue;
            if (result < 0) {
                return switch (-result) {
                    os.EINTR => continue,
                    os.EAGAIN => return error.WouldBlock,
                    os.EBADF => unreachable,
                    os.ECONNABORTED => return error.ConnectionAborted,
                    os.EFAULT => unreachable,
                    os.EINVAL => return error.SocketNotListening,
                    os.ENOTSOCK => unreachable,
                    os.EMFILE => return error.ProcessFdQuotaExceeded,
                    os.ENFILE => return error.SystemFdQuotaExceeded,
                    os.ENOBUFS => return error.SystemResources,
                    os.ENOMEM => return error.SystemResources,
                    os.EOPNOTSUPP => unreachable,
                    os.EPROTO => return error.ProtocolFailure,
                    os.EPERM => return error.BlockedByFirewall,
                    else => |err| return os.unexpectedErrno(err),
                };
            }

            const socket = Socket{ .fd = @intCast(os.socket_t, result) };
            const socket_address = Socket.Address.fromNative(@ptrCast(*os.sockaddr, &address));

            return Socket.Connection.from(socket, socket_address);
        }
    }
};

test {
    testing.refAllDecls(@This());
}

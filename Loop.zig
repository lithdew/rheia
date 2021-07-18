const std = @import("std");

const os = std.os;
const mem = std.mem;
const time = std.time;
const testing = std.testing;

const assert = std.debug.assert;

const Socket = std.x.os.Socket;
const Atomic = std.atomic.Atomic;

const Ring = os.linux.IO_Uring;
const Submission = os.linux.io_uring_sqe;
const Completion = os.linux.io_uring_cqe;

const Loop = @This();

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
        await self.frame catch |err| return switch (err) {
            error.DeadlineExceeded => {},
            else => err,
        };
    }

    pub fn waitFor(self: *Loop.Timer, params: Loop.Timer.Params) !void {
        self.start(params);
        return self.wait();
    }

    pub fn cancel(self: *Loop.Timer) void {
        var waiter: Loop.Waiter = .{ .frame = @frame() };

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = blk: {
                    _ = self.loop.ring.timeout_remove(
                        @ptrToInt(&waiter.node),
                        @ptrToInt(&self.waiter.node),
                        0,
                    ) catch |err| {
                        self.loop.submissions.append(&waiter.node);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :blk err,
                        }
                    };
                    break :blk null;
                };
            }
            if (maybe_err) |err| std.debug.panic("{}", .{err});

            const result = waiter.result orelse continue;
            return switch (-result) {
                0 => {},
                os.ENOENT => {},
                os.EBUSY => {},
                else => |err| std.debug.panic("{}", .{os.unexpectedErrno(err)}),
            };
        }
    }

    fn handle(self: *Loop.Timer, params: Loop.Timer.Params) !void {
        const timespec: os.__kernel_timespec = .{
            .tv_sec = params.seconds,
            .tv_nsec = params.nanoseconds,
        };

        self.waiter = .{ .frame = @frame() };

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = blk: {
                    _ = self.loop.ring.timeout(
                        @ptrToInt(&self.waiter.node),
                        &timespec,
                        0,
                        @enumToInt(params.mode),
                    ) catch |err| {
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
                os.ETIME => error.DeadlineExceeded,
                os.ECANCELED => error.Cancelled,
                else => |err| os.unexpectedErrno(err),
            };
        }
    }
};

ring: Ring,

notifier: struct {
    armed: Atomic(bool) = .{ .value = false },
    rearm_required: bool = true,
    buffer: u64 = undefined,
    fd: os.fd_t,
},

submissions: std.TailQueue(void) = .{},
completions: std.TailQueue(void) = .{},

pub fn init(self: *Loop, maybe_params: ?*os.linux.io_uring_params) !void {
    var ring = try if (maybe_params) |params| Ring.init_params(4096, params) else Ring.init(4096, 0);
    errdefer ring.deinit();

    const notifier_fd = try os.eventfd(0, os.O_CLOEXEC);
    errdefer os.close(notifier_fd);

    self.* = .{ .ring = ring, .notifier = .{ .fd = notifier_fd } };
}

pub fn deinit(self: *Loop) void {
    self.ring.deinit();
}

pub fn hasPendingTasks(self: *Loop) bool {
    return self.submissions.len > 0 or self.completions.len > 0;
}

pub fn notify(self: *Loop) void {
    if (!self.notifier.armed.swap(false, .AcqRel)) return;
    const bytes_written = os.write(self.notifier.fd, mem.asBytes(&@as(u64, 1))) catch unreachable;
    assert(bytes_written == @sizeOf(u64));
}

fn reset(self: *Loop) void {
    if (self.ring.read(0, self.notifier.fd, mem.asBytes(&self.notifier.buffer), 0)) |_| {
        self.notifier.armed.store(true, .Release);
        self.notifier.rearm_required = false;
    } else |_| {
        self.notifier.rearm_required = true;
    }
}

pub fn poll(self: *Loop, blocking: bool) !usize {
    var completions: [4096]Completion = undefined;
    var count: usize = 0;

    _ = self.ring.submit_and_wait(wait_count: {
        if (self.hasPendingTasks()) {
            break :wait_count 0;
        }
        if (self.notifier.rearm_required and blocking) {
            self.reset();
            break :wait_count 0;
        }
        break :wait_count @as(u32, if (blocking) 1 else 0);
    }) catch |err| switch (err) {
        error.CompletionQueueOvercommitted, error.SystemResources => 0,
        error.SignalInterrupt => return count,
        else => return err,
    };

    const completion_count = try self.ring.copy_cqes(&completions, 0);
    for (completions[0..completion_count]) |completion| {
        if (completion.user_data == 0) {
            self.notifier.rearm_required = true;
            continue;
        }

        const waiter = @intToPtr(*Waiter, completion.user_data);
        waiter.result = completion.res;
        self.completions.append(&waiter.node);
    }

    var it: std.TailQueue(void) = .{};
    mem.swap(std.TailQueue(void), &it, &self.submissions);
    count += it.len;
    while (it.popFirst()) |node| {
        const waiter = @fieldParentPtr(Waiter, "node", node);
        resume waiter.frame;
    }
    if (count > 0) return count;

    mem.swap(std.TailQueue(void), &it, &self.completions);
    count += it.len;
    while (it.popFirst()) |node| {
        const waiter = @fieldParentPtr(Waiter, "node", node);
        resume waiter.frame;
    }

    return count;
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
                os.EBADF => return error.NotOpenForWriting,
                os.EDESTADDRREQ => unreachable,
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
                os.EBADF => unreachable,
                os.ECONNRESET => error.ConnectionResetByPeer,
                os.EDESTADDRREQ => unreachable,
                os.EFAULT => unreachable,
                os.EINTR => continue,
                os.EINVAL => unreachable,
                os.EISCONN => unreachable,
                os.EMSGSIZE => error.MessageTooBig,
                os.ENOBUFS => error.SystemResources,
                os.ENOMEM => error.SystemResources,
                os.ENOTSOCK => unreachable,
                os.EOPNOTSUPP => unreachable,
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
                _ = self.ring.connect(
                    @ptrToInt(&waiter),
                    fd,
                    @ptrCast(*const os.sockaddr, &address.toNative()),
                    address.getNativeSize(),
                ) catch |err| {
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
                os.EBADF => unreachable,
                os.ECONNREFUSED => error.ConnectionRefused,
                os.ECONNRESET => error.ConnectionResetByPeer,
                os.EFAULT => unreachable,
                os.EINTR => continue,
                os.EISCONN => unreachable,
                os.ENETUNREACH => error.NetworkUnreachable,
                os.ENOTSOCK => unreachable,
                os.EPROTOTYPE => unreachable,
                os.ETIMEDOUT => error.ConnectionTimedOut,
                os.ENOENT => error.FileNotFound,
                else => |err| os.unexpectedErrno(err),
            };
        }

        return;
    }
}

pub fn accept(
    self: *Loop,
    fd: os.socket_t,
    flags: std.enums.EnumFieldStruct(Socket.InitFlags, bool, false),
) !Socket.Connection {
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
                _ = self.ring.accept(
                    @ptrToInt(&waiter),
                    fd,
                    @ptrCast(*os.sockaddr, &address),
                    &address_len,
                    raw_flags,
                ) catch |err| {
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

test "loop: cancel timeout" {
    var loop: Loop = undefined;
    try loop.init(null);
    defer loop.deinit();

    var timer = Loop.Timer.init(&loop);

    var submit_frame = async timer.waitFor(.{ .seconds = 3 });
    try testing.expectEqual(@as(usize, 0), try loop.poll(false));

    var cancel_frame = async timer.cancel();
    try testing.expectEqual(@as(usize, 2), try loop.poll(true));

    nosuspend await cancel_frame;
    try testing.expectError(error.Cancelled, nosuspend await submit_frame);
}

test "loop: start timeout" {
    var loop: Loop = undefined;
    try loop.init(null);
    defer loop.deinit();

    var timer = Loop.Timer.init(&loop);

    var submit_frame = async timer.waitFor(.{ .nanoseconds = 100 * time.ns_per_ms });
    try testing.expectEqual(@as(usize, 0), try loop.poll(true));

    try testing.expectEqual(@as(usize, 1), try loop.poll(true));
    try nosuspend await submit_frame;
}

const std = @import("std");

const os = std.os;
const ip = std.x.net.ip;

const mem = std.mem;
const testing = std.testing;

const assert = std.debug.assert;

const Socket = std.x.os.Socket;
const Atomic = std.atomic.Atomic;

const Ring = os.linux.IO_Uring;
const Submission = os.linux.io_uring_sqe;
const Completion = os.linux.io_uring_cqe;
const RingParams = os.linux.io_uring_params;

pub const Worker = struct {
    const log = std.log.scoped(.io_worker);

    shutdown_requested: Atomic(bool) = .{ .value = false },
    loop: Loop,

    pub fn init(self: *Worker) !void {
        var loop: Loop = undefined;
        try loop.init(null);
        errdefer loop.deinit();

        self.* = .{ .loop = loop };
    }

    pub fn deinit(self: *Worker) void {
        self.loop.deinit();
    }

    pub fn shutdown(self: *Worker) void {
        self.shutdown_requested.store(true, .Release);
        self.loop.notify();
    }

    pub fn run(self: *Worker) !void {
        defer log.debug("worker {} is done", .{std.Thread.getCurrentId()});

        log.debug("worker {} started", .{std.Thread.getCurrentId()});

        while (true) {
            try self.loop.poll();
            if (self.shutdown_requested.load(.Acquire)) {
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

    ring: Ring,

    notifier: struct {
        notified: Atomic(bool) = .{ .value = false },
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
        self.reset();
    }

    pub fn deinit(self: *Loop) void {
        self.ring.deinit();
    }

    pub fn notify(self: *Loop) void {
        if (self.notifier.notified.swap(true, .AcqRel)) return;

        const bytes_written = os.write(self.notifier.fd, mem.asBytes(&@as(u64, 1))) catch {
            self.notifier.notified.store(false, .Release);
            return;
        };

        assert(bytes_written == @sizeOf(u64));
    }

    pub fn reset(self: *Loop) void {
        _ = self.ring.read(0, self.notifier.fd, mem.asBytes(&self.notifier.buffer), 0) catch {};
        self.notifier.notified.store(false, .Release);
    }

    pub fn poll(self: *Loop) !void {
        var completions: [256]Completion = undefined;

        self.pending += self.ring.submit_and_wait(wait_count: {
            if (self.submissions.len > 0 or self.completions.len > 0 or self.ring.cq_ready() > 0) {
                break :wait_count 0;
            }
            break :wait_count 1;
        }) catch |err| switch (err) {
            error.CompletionQueueOvercommitted, error.SystemResources => 0,
            error.SignalInterrupt => return,
            else => return err,
        };

        const completion_count = try self.ring.copy_cqes(&completions, 0);
        for (completions[0..completion_count]) |completion| {
            if (completion.user_data == 0) {
                self.pending -= 1;
                self.reset();
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

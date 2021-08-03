const std = @import("std");

pub const log_level = .info;

pub var count: std.atomic.Atomic(u64) = .{ .value = 0 };
pub const message = &([_]u8{0} ** 10);

pub fn main() !void {
    var threads: [3]std.Thread = undefined;

    var thread_index: usize = 0;
    defer for (threads[0..thread_index]) |*thread| thread.join();

    while (thread_index < threads.len) : (thread_index += 1) {
        threads[thread_index] = try std.Thread.spawn(.{}, run, .{1 + thread_index});
    }

    try run(0);
}

pub fn run(thread_index: usize) !void {
    var worker = try Worker.init();
    defer worker.deinit();

    var frame = async runConnection(&worker, thread_index);
    defer nosuspend await frame catch |err| std.log.warn("{}", .{err});

    while (true) {
        try worker.tick();
    }
}

pub fn runConnection(worker: *Worker, thread_index: usize) !void {
    const client = try std.x.net.tcp.Client.init(.ip, .{ .close_on_exec = true, .nonblocking = true });
    defer client.deinit();

    try client.setNoDelay(true);

    try worker.connect(client.socket, std.x.os.Socket.Address.initIPv4(std.x.os.IPv4.localhost, 9000));

    var writer = (AsyncSocket{ .worker = worker, .socket = client.socket }).writer();

    var buffer = try std.heap.c_allocator.alloc(u8, 1 * 1024 * 1024);
    defer std.heap.c_allocator.free(buffer);

    var fifo = std.fifo.LinearFifo(u8, .Slice).init(buffer);
    var timer = try std.time.Timer.start();

    while (true) {
        if (thread_index == 0 and timer.read() > 1 * std.time.ns_per_s) {
            std.log.info("# messages sent in the last second: {}", .{count.swap(0, .Monotonic)});
            timer.reset();
        }

        var index: usize = 0;
        while (index < message.len) {
            if (message[index..].len >= fifo.writableLength()) {
                while (true) {
                    const slice = fifo.readableSlice(0);
                    if (slice.len == 0) break;
                    try writer.writeAll(slice);
                    fifo.discard(slice.len);
                }
                continue;
            }

            fifo.writeAssumeCapacity(message[index..]);
            index += message[index..].len;
        }

        _ = count.fetchAdd(1, .Monotonic);
    }
}

pub const Task = struct {
    node: std.SinglyLinkedList(void).Node = .{ .data = {} },
    result: ?isize = null,
    frame: anyframe,
};

pub const AsyncSocket = struct {
    worker: *Worker,
    socket: std.x.os.Socket,
    write_flags: u32 = std.os.MSG_NOSIGNAL,

    fn ErrorSetOf(comptime F: anytype) type {
        return @typeInfo(@typeInfo(@TypeOf(F)).Fn.return_type.?).ErrorUnion.error_set;
    }

    pub fn writer(self: AsyncSocket) std.io.Writer(AsyncSocket, ErrorSetOf(AsyncSocket.write), AsyncSocket.write) {
        return .{ .context = self };
    }

    pub fn write(self: AsyncSocket, buffer: []const u8) !usize {
        return self.worker.send(self.socket, buffer, self.write_flags);
    }
};

pub const Worker = struct {
    ring: std.os.linux.IO_Uring,
    submissions: std.SinglyLinkedList(void) = .{},
    completions: std.SinglyLinkedList(void) = .{},

    pub fn init() !Worker {
        var ring = try std.os.linux.IO_Uring.init(4096, 0);
        errdefer ring.deinit();

        return Worker{ .ring = ring };
    }

    pub fn deinit(self: *Worker) void {
        self.ring.deinit();
    }

    pub fn send(self: *Worker, socket: std.x.os.Socket, buffer: []const u8, flags: u32) !usize {
        return socket.write(buffer, flags) catch |send_err| switch (send_err) {
            error.WouldBlock => {
                var task: Task = .{ .frame = @frame() };

                while (true) {
                    var maybe_err: ?anyerror = null;

                    suspend {
                        maybe_err = blk: {
                            _ = self.ring.send(@ptrToInt(&task), socket.fd, buffer, flags) catch |err| {
                                self.submissions.prepend(&task.node);
                                switch (err) {
                                    error.SubmissionQueueFull => {},
                                    else => break :blk err,
                                }
                            };
                            break :blk null;
                        };
                    }

                    if (maybe_err) |err| return err;

                    const result = task.result orelse continue;
                    if (result < 0) {
                        return switch (-result) {
                            std.os.ECONNREFUSED => error.ConnectionRefused,
                            std.os.EACCES => error.AccessDenied,
                            std.os.EAGAIN => error.WouldBlock,
                            std.os.EALREADY => error.FastOpenAlreadyInProgress,
                            std.os.EBADF => unreachable,
                            std.os.ECONNRESET => error.ConnectionResetByPeer,
                            std.os.EDESTADDRREQ => unreachable,
                            std.os.EFAULT => unreachable,
                            std.os.EINTR => continue,
                            std.os.EINVAL => unreachable,
                            std.os.EISCONN => unreachable,
                            std.os.EMSGSIZE => error.MessageTooBig,
                            std.os.ENOBUFS => error.SystemResources,
                            std.os.ENOMEM => error.SystemResources,
                            std.os.ENOTSOCK => unreachable,
                            std.os.EOPNOTSUPP => unreachable,
                            std.os.EPIPE => error.BrokenPipe,
                            std.os.EAFNOSUPPORT => error.AddressFamilyNotSupported,
                            std.os.ELOOP => error.SymLinkLoop,
                            std.os.ENAMETOOLONG => error.NameTooLong,
                            std.os.ENOENT => error.FileNotFound,
                            std.os.ENOTDIR => error.NotDir,
                            std.os.EHOSTUNREACH => error.NetworkUnreachable,
                            std.os.ENETUNREACH => error.NetworkUnreachable,
                            std.os.ENOTCONN => error.SocketNotConnected,
                            std.os.ENETDOWN => error.NetworkSubsystemFailed,
                            else => |err| std.os.unexpectedErrno(err),
                        };
                    }
                    return @intCast(usize, result);
                }
            },
            else => return send_err,
        };
    }

    pub fn connect(self: *Worker, socket: std.x.os.Socket, address: std.x.os.Socket.Address) !void {
        var task: Task = .{ .frame = @frame() };

        while (true) {
            var maybe_err: ?anyerror = null;

            suspend {
                maybe_err = blk: {
                    _ = self.ring.connect(@ptrToInt(&task), socket.fd, @ptrCast(*const std.os.sockaddr, &address.toNative()), address.getNativeSize()) catch |err| {
                        self.submissions.prepend(&task.node);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :blk err,
                        }
                    };
                    break :blk null;
                };
            }

            if (maybe_err) |err| return err;

            const result = task.result orelse continue;
            if (result < 0) {
                return switch (-result) {
                    std.os.EACCES => error.PermissionDenied,
                    std.os.EPERM => error.PermissionDenied,
                    std.os.EADDRINUSE => error.AddressInUse,
                    std.os.EADDRNOTAVAIL => error.AddressNotAvailable,
                    std.os.EAFNOSUPPORT => error.AddressFamilyNotSupported,
                    std.os.EAGAIN, std.os.EINPROGRESS => error.WouldBlock,
                    std.os.EALREADY => error.ConnectionPending,
                    std.os.EBADF => unreachable,
                    std.os.ECONNREFUSED => error.ConnectionRefused,
                    std.os.ECONNRESET => error.ConnectionResetByPeer,
                    std.os.EFAULT => unreachable,
                    std.os.EINTR => continue,
                    std.os.EISCONN => unreachable,
                    std.os.ENETUNREACH => error.NetworkUnreachable,
                    std.os.ENOTSOCK => unreachable,
                    std.os.EPROTOTYPE => unreachable,
                    std.os.ETIMEDOUT => error.ConnectionTimedOut,
                    std.os.ENOENT => error.FileNotFound,
                    else => |err| std.os.unexpectedErrno(err),
                };
            }
            return;
        }
    }

    pub fn tick(self: *Worker) !void {
        _ = self.ring.submit_and_wait(1) catch |err| switch (err) {
            error.CompletionQueueOvercommitted, error.SystemResources => {},
            else => return err,
        };

        var completions: [4096]std.os.linux.io_uring_cqe = undefined;

        const num_completions = try self.ring.copy_cqes(&completions, 0);
        for (completions[0..num_completions]) |completion| {
            const node = @intToPtr(*std.SinglyLinkedList(void).Node, completion.user_data);
            const task = @fieldParentPtr(Task, "node", node);
            task.result = completion.res;
            self.completions.prepend(node);
        }

        var it: std.SinglyLinkedList(void) = .{};
        var later = it.first != null;

        std.mem.swap(std.SinglyLinkedList(void), &it, &self.submissions);
        while (it.popFirst()) |node| {
            const task = @fieldParentPtr(Task, "node", node);
            resume task.frame;
        }

        if (later) return;

        std.mem.swap(std.SinglyLinkedList(void), &it, &self.completions);
        while (it.popFirst()) |node| {
            const task = @fieldParentPtr(Task, "node", node);
            resume task.frame;
        }
    }
};

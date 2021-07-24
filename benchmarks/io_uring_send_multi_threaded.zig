const std = @import("std");

pub const log_level = .debug;

const num_threads = 4;

var packets_per_second = std.atomic.Atomic(usize).init(0);

pub fn main() !void {
    var thread_rings: [num_threads]std.os.linux.IO_Uring = undefined;

    var thread_ring_index: usize = 0;
    errdefer for (thread_rings[0..thread_ring_index]) |*thread_ring| thread_ring.deinit();

    while (thread_ring_index < thread_rings.len) : (thread_ring_index += 1) {
        var params = switch (thread_ring_index) {
            0 => std.mem.zeroInit(std.os.linux.io_uring_params, .{
                .flags = 0,
                .sq_thread_cpu = @intCast(u32, thread_ring_index),
                .sq_thread_idle = 1000,
            }),
            else => std.mem.zeroInit(std.os.linux.io_uring_params, .{
                .flags = std.os.IORING_SETUP_ATTACH_WQ,
                .wq_fd = @intCast(u32, thread_rings[0].fd),
                .sq_thread_cpu = @intCast(u32, thread_ring_index),
                .sq_thread_idle = 1000,
            }),
        };

        thread_rings[thread_ring_index] = try std.os.linux.IO_Uring.init_params(4096, &params);
    }

    var threads: [num_threads - 1]std.Thread = undefined;

    var thread_index: usize = 0;
    defer for (threads[0..thread_index]) |*thread| thread.join();

    while (thread_index < threads.len) : (thread_index += 1) {
        threads[thread_index] = try std.Thread.spawn(.{}, run, .{ &thread_rings[thread_index + 1], false });
    }

    try run(&thread_rings[0], true);
}

pub fn run(ring: *std.os.linux.IO_Uring, print: bool) !void {
    defer ring.deinit();

    const client = try std.x.net.tcp.Client.init(.ip, .{ .close_on_exec = true, .nonblocking = true });
    defer client.deinit();

    try client.setNoDelay(true);

    client.connect(std.x.net.ip.Address.initIPv4(std.x.os.IPv4.localhost, 9000)) catch |err| switch (err) {
        error.WouldBlock => try client.getError(),
        else => return err,
    };

    var completions: [4096]std.os.linux.io_uring_cqe = undefined;

    var timer = try std.time.Timer.start();

    while (true) {
        if (print and timer.read() > 1 * std.time.ns_per_s) {
            std.log.info("sent {} packet(s) in the last second", .{packets_per_second.swap(0, .Monotonic)});
            timer.reset();
        }

        while (true) {
            _ = ring.send(0, client.socket.fd, &([_]u8{0} ** (10)), std.os.MSG_NOSIGNAL) catch |err| switch (err) {
                error.SubmissionQueueFull => break,
                else => return err,
            };
        }

        _ = ring.submit_and_wait(1) catch |err| switch (err) {
            error.CompletionQueueOvercommitted, error.SystemResources => {},
            else => return err,
        };

        const num_completions = try ring.copy_cqes(&completions, 0);
        for (completions[0..num_completions]) |completion| {
            if (completion.res < 0) {
                return switch (-completion.res) {
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
        }

        _ = packets_per_second.fetchAdd(num_completions, .Monotonic);
    }
}

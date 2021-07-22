const std = @import("std");

pub const log_level = .debug;

pub fn main() !void {
    var ring = try std.os.linux.IO_Uring.init(4096, 0);
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
    var packets_per_second: usize = 0;

    while (true) {
        if (timer.read() > 1 * std.time.ns_per_s) {
            std.log.info("sent {} packet(s) in the last second", .{packets_per_second});
            packets_per_second = 0;
            timer.reset();
        }

        while (true) {
            _ = ring.send(0, client.socket.fd, &([_]u8{0} ** 10), std.os.MSG_NOSIGNAL) catch |err| switch (err) {
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

        packets_per_second += num_completions;
    }
}

const std = @import("std");

const mem = std.mem;

const ip = std.x.net.ip;
const tcp = std.x.net.tcp;
const log = std.log.scoped(.rheia);

const assert = std.debug.assert;

const IPv4 = std.x.os.IPv4;
const Socket = std.x.os.Socket;

const Loop = @import("io.zig").Loop;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer assert(!gpa.deinit());

    const allocator = &gpa.allocator;

    var loop: Loop = undefined;
    try loop.init(null);
    defer loop.deinit();

    var listener = try tcp.Listener.init(.ip, .{ .close_on_exec = true });
    defer listener.deinit();

    try listener.bind(ip.Address.initIPv4(IPv4.localhost, 0));
    try listener.listen(128);

    log.info("tcp: listening for peers on {}", .{try listener.getLocalAddress()});

    var listener_frame = async runListener(allocator, &loop, listener);
    defer nosuspend await listener_frame catch |err| log.emerg("{}", .{err});

    try loop.run();
}

pub fn runListener(gpa: *mem.Allocator, loop: *Loop, listener: tcp.Listener) !void {
    while (true) {
        const conn = loop.accept(listener.socket.fd, .{ .close_on_exec = true }) catch |err| return err;
        errdefer conn.socket.deinit();

        const frame = try gpa.create(@Frame(runConnection));
        errdefer gpa.destroy(frame);

        frame.* = async runConnection(gpa, loop, tcp.Connection.from(conn));
    }
}

pub fn runConnection(gpa: *mem.Allocator, loop: *Loop, conn: tcp.Connection) !void {
    defer {
        conn.deinit();
        suspend gpa.destroy(@frame());
    }

    log.debug("new peer connected: {}", .{conn.address});

    var buffer: [256]u8 = undefined;

    while (true) {
        const num_bytes_read = loop.recv(conn.client.socket.fd, &buffer, 0) catch |err| return err;
        if (num_bytes_read == 0) return;

        log.debug("got message: '{s}'", .{mem.trim(u8, buffer[0..num_bytes_read], " \t\r\n")});
    }
}

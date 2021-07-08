const std = @import("std");

const mem = std.mem;

const ip = std.x.net.ip;
const tcp = std.x.net.tcp;
const log = std.log.scoped(.rheia);

const IPv4 = std.x.os.IPv4;
const Socket = std.x.os.Socket;

const Runtime = @import("runtime.zig").Runtime;

pub fn main() !void {
    var runtime = try Runtime.init();
    defer runtime.deinit();

    var frame = async run(&runtime);
    defer nosuspend await frame catch |err| log.emerg("{}", .{err});

    try runtime.io_workers.items[0].run();
}

pub fn run(runtime: *Runtime) !void {
    var next_io_worker_index: usize = 0;

    var listener = try tcp.Listener.init(.ip, .{ .close_on_exec = true });
    defer listener.deinit();

    try listener.bind(ip.Address.initIPv4(IPv4.localhost, 0));
    try listener.listen(128);

    log.info("tcp: listening for peers on {}", .{try listener.getLocalAddress()});

    var client_frame = async runClient(runtime, try listener.getLocalAddress());
    defer await client_frame catch |err| log.emerg("{}", .{err});

    while (true) {
        const conn = runtime.io_workers.items[0].loop.accept(listener.socket.fd, .{ .close_on_exec = true }) catch |err| return err;
        errdefer conn.socket.deinit();

        const frame = try runtime.gpa.allocator.create(@Frame(runConnection));
        errdefer gpa.destroy(frame);

        frame.* = async runConnection(runtime, next_io_worker_index, tcp.Connection.from(conn));
        runtime.io_workers.items[next_io_worker_index].loop.notify();

        next_io_worker_index = (next_io_worker_index + 1) % runtime.io_workers.items.len;
    }
}

pub fn runClient(runtime: *Runtime, address: ip.Address) !void {
    var client = try tcp.Client.init(.ip, .{ .close_on_exec = true });
    defer client.deinit();

    try runtime.io_workers.items[0].loop.connect(client.socket.fd, address.into());
    _ = try runtime.io_workers.items[0].loop.send(client.socket.fd, "hello world!\n", 0);
}

pub fn runConnection(runtime: *Runtime, io_worker_index: usize, conn: tcp.Connection) !void {
    defer {
        suspend runtime.gpa.allocator.destroy(@frame());
    }

    defer log.debug("peer disconnected: {}", .{conn.address});
    defer conn.deinit();

    log.debug("new peer connected: {}", .{conn.address});

    var buffer: [256]u8 = undefined;

    while (true) {
        const num_bytes_read = runtime.io_workers.items[io_worker_index].loop.recv(conn.client.socket.fd, &buffer, 0) catch |err| return err;
        if (num_bytes_read == 0) return;

        log.debug("{}: got message: '{s}'", .{ conn.address, mem.trim(u8, buffer[0..num_bytes_read], " \t\r\n") });
    }
}

const std = @import("std");

const os = std.os;
const mem = std.mem;

const ip = std.x.net.ip;
const tcp = std.x.net.tcp;
const log = std.log.scoped(.rheia);

const assert = std.debug.assert;

const IPv4 = std.x.os.IPv4;

const Runtime = @import("Runtime.zig");
const Server = @import("Server.zig");

pub fn main() !void {
    var runtime = try Runtime.init();
    defer runtime.deinit();

    try runtime.start();

    var frame = async run(&runtime);
    try runtime.io_workers.items[0].run();
    try nosuspend await frame;
    runtime.waitForShutdown();

    log.info("shutdown successful", .{});
}

pub fn run(runtime: *Runtime) !void {
    defer runtime.shutdown();

    var server = Server.init();
    defer {
        server.shutdown();
        server.waitForShutdown();
        server.deinit(&runtime.gpa.allocator);
    }

    var listener = try tcp.Listener.init(.ip, .{ .close_on_exec = true });
    defer listener.deinit();

    try listener.setReuseAddress(true);
    try listener.setFastOpen(true);

    try listener.bind(ip.Address.initIPv4(IPv4.localhost, 9000));
    try listener.listen(128);

    const listen_address = try listener.getLocalAddress();

    var listener_frame = async server.serve(runtime, listener);
    defer await listener_frame catch |err| log.warn("listener error: {}", .{err});

    log.info("tcp: listening for peers on {}", .{listen_address});

    var client = try tcp.Client.init(.ip, .{ .close_on_exec = true });
    defer client.deinit();

    try runtime.io_workers.items[0].loop.connect(client.socket.fd, listen_address.into());

    var client_frame = async runClient(runtime, client);
    defer await client_frame catch |err| log.warn("client error: {}", .{err});

    try runtime.waitForSignal();

    log.info("gracefully shutting down...", .{});

    try listener.shutdown();
    try client.shutdown(.both);
}

pub fn runClient(runtime: *Runtime, client: tcp.Client) !void {
    const message = "hello world!\n";

    var bytes_written: usize = 0;
    while (bytes_written < message.len) {
        bytes_written += try runtime.io_workers.items[0].loop.send(client.socket.fd, message, os.MSG_NOSIGNAL);
    }
}

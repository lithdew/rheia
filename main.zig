const std = @import("std");

const os = std.os;
const mem = std.mem;

const ip = std.x.net.ip;
const tcp = std.x.net.tcp;
const log = std.log.scoped(.rheia);

const assert = std.debug.assert;

const IPv4 = std.x.os.IPv4;

const Loop = @import("Loop.zig");
const Server = @import("Server.zig");
const Client = @import("Client.zig");
const Runtime = @import("Runtime.zig");

pub const log_level = .debug;

pub fn main() !void {
    defer log.info("shutdown successful", .{});

    var runtime: Runtime = undefined;
    try runtime.init();
    defer {
        runtime.waitForShutdown();
        runtime.deinit();
    }

    try runtime.start();

    var frame = async run(&runtime);
    try runtime.workers.items[0].run();
    try nosuspend await frame;
}

pub fn run(runtime: *Runtime) !void {
    defer runtime.shutdown();

    var server = Server.init();
    defer {
        server.shutdown();
        server.waitForShutdown();
        server.deinit(runtime.gpa);
    }

    var listener = try tcp.Listener.init(.ip, .{ .close_on_exec = true });
    defer listener.deinit();

    try listener.setReuseAddress(true);
    try listener.setFastOpen(true);

    try listener.bind(ip.Address.initIPv4(IPv4.localhost, 9000));
    try listener.listen(128);

    const listen_address = try listener.getLocalAddress();

    var listener_frame = async server.serve(runtime, listener);
    defer {
        listener.shutdown() catch |err| log.warn("listener shutdown error: {}", .{err});
        await listener_frame catch |err| log.warn("listener error: {}", .{err});
    }

    log.info("tcp: listening for peers on {}", .{listen_address});

    var client = try Client.init(runtime.gpa, runtime, ip.Address.initIPv4(IPv4.localhost, 9000));
    defer {
        client.waitForShutdown();
        client.deinit(runtime.gpa);
    }

    var timer = Loop.Timer.init(&runtime.workers.items[0].loop);
    var client_frame = async runClient(runtime, &timer, &client);
    defer {
        timer.cancel();
        client.shutdown();
        await client_frame catch |err| log.warn("client error: {}", .{err});
    }

    try runtime.waitForSignal();

    log.info("gracefully shutting down...", .{});
}

fn runClient(runtime: *Runtime, _: *Loop.Timer, client: *Client) !void {
    // log.info("starting benchmark in 3...", .{});
    // try timer.waitFor(.{ .seconds = 1 });
    // log.info("starting benchmark in 2...", .{});
    // try timer.waitFor(.{ .seconds = 1 });
    // log.info("starting benchmark in 1...", .{});
    // try timer.waitFor(.{ .seconds = 1 });

    var i: usize = 0;
    while (i < 100_000_000) : (i += 1) {
        try await async client.write(runtime, "hello world!\n");
        runtime.yield(0, 0);
    }

    log.info("done!", .{});
}

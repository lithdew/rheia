const std = @import("std");

const os = std.os;
const mem = std.mem;

const ip = std.x.net.ip;
const tcp = std.x.net.tcp;
const log = std.log.scoped(.rheia);

const assert = std.debug.assert;

const IPv4 = std.x.os.IPv4;
const Socket = std.x.os.Socket;
const Atomic = std.atomic.Atomic;

const Runtime = @import("runtime.zig").Runtime;

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

    var listener = try tcp.Listener.init(.ip, .{ .close_on_exec = true });
    defer listener.deinit();

    try listener.setReuseAddress(true);
    try listener.setFastOpen(true);

    try listener.bind(ip.Address.initIPv4(IPv4.localhost, 9000));
    try listener.listen(128);

    const listen_address = try listener.getLocalAddress();

    var listener_frame = async runListener(runtime, listener);
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

pub const Server = struct {
    connections: struct {
        lock: std.Thread.Mutex = .{},
        entries: std.AutoArrayHashMapUnmanaged(*@Frame(runConnection), tcp.Connection) = .{},
    },

    live_connections: struct {
        count: Atomic(usize) = .{ .value = 0 },
        waiter: Atomic(usize) = .{ .value = 0 },
    },

    pub fn init() Server {
        return .{ .connections = .{}, .live_connections = .{} };
    }

    pub fn deinit(self: *Server, gpa: *mem.Allocator) void {
        self.connections.entries.deinit(gpa);
    }

    pub fn shutdown(self: *Server) void {
        const held = self.connections.lock.acquire();
        defer held.release();

        var it = self.connections.entries.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.client.shutdown(.recv) catch {};
        }
    }

    pub fn waitForShutdown(self: *Server) void {
        while (self.live_connections.count.load(.Monotonic) > 0) {
            suspend self.live_connections.waiter.store(@ptrToInt(@frame()), .Release);
        }
    }

    pub fn register(self: *Server, gpa: *mem.Allocator, frame: *@Frame(runConnection), conn: tcp.Connection) !void {
        const held = self.connections.lock.acquire();
        defer held.release();

        try self.connections.entries.put(gpa, frame, conn);
        _ = self.live_connections.count.fetchAdd(1, .Monotonic);
    }

    pub fn deregister(self: *Server, gpa: *mem.Allocator, frame: *@Frame(runConnection)) void {
        const maybe_waiter = grab: {
            const held = self.connections.lock.acquire();
            defer held.release();

            if (self.connections.entries.swapRemove(frame)) {
                gpa.destroy(frame);

                if (self.live_connections.count.fetchSub(1, .Release) == 1) {
                    const maybe_waiter = self.live_connections.waiter.swap(0, .Release);
                    if (maybe_waiter != 0) break :grab maybe_waiter;
                }
            }

            break :grab null;
        };

        if (maybe_waiter) |waiter| {
            resume @intToPtr(anyframe, waiter);
        }
    }
};

pub fn runListener(runtime: *Runtime, listener: tcp.Listener) !void {
    defer log.info("listener: successfully shut down", .{});

    var server = Server.init();
    defer {
        server.shutdown();
        server.waitForShutdown();
        server.deinit(&runtime.gpa.allocator);
    }

    var next_io_worker_index: usize = 0;

    while (true) {
        const conn = runtime.io_workers.items[0].loop.accept(listener.socket.fd, .{ .close_on_exec = true }) catch |err| switch (err) {
            error.SocketNotListening => return,
            else => return err,
        };
        errdefer conn.socket.deinit();

        const frame = try runtime.gpa.allocator.create(@Frame(runConnection));
        errdefer runtime.gpa.allocator.destroy(frame);

        try server.register(&runtime.gpa.allocator, frame, tcp.Connection.from(conn));
        errdefer server.deregister(&runtime.gpa.allocator, frame);

        frame.* = async runConnection(runtime, &server, next_io_worker_index, tcp.Connection.from(conn));
        runtime.io_workers.items[next_io_worker_index].loop.notify();

        next_io_worker_index = (next_io_worker_index + 1) % runtime.io_workers.items.len;
    }
}

pub fn runClient(runtime: *Runtime, client: tcp.Client) !void {
    const message = "hello world!\n";

    var bytes_written: usize = 0;
    while (bytes_written < message.len) {
        bytes_written += try runtime.io_workers.items[0].loop.send(client.socket.fd, message, os.MSG_NOSIGNAL);
    }
}

pub fn runConnection(runtime: *Runtime, server: *Server, io_worker_index: usize, conn: tcp.Connection) !void {
    defer {
        conn.deinit();
        suspend server.deregister(&runtime.gpa.allocator, @frame());
    }

    log.debug("new peer connected: {}", .{conn.address});
    defer log.debug("peer disconnected: {}", .{conn.address});

    var buffer: [256]u8 = undefined;

    while (true) {
        const num_bytes_read = runtime.io_workers.items[io_worker_index].loop.recv(conn.client.socket.fd, &buffer, 0) catch |err| return err;
        if (num_bytes_read == 0) break;

        log.debug("{}: got message: '{s}'", .{ conn.address, mem.trim(u8, buffer[0..num_bytes_read], " \t\r\n") });
    }
}

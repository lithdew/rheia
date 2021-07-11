const std = @import("std");

const mem = std.mem;
const tcp = std.x.net.tcp;
const log = std.log.scoped(.server);

const Atomic = std.atomic.Atomic;
const Runtime = @import("Runtime.zig");

const Server = @This();

connections: struct {
    lock: std.Thread.Mutex = .{},
    entries: std.AutoArrayHashMapUnmanaged(*@Frame(Server.serveConnection), tcp.Connection) = .{},
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

pub fn serve(self: *Server, runtime: *Runtime, listener: tcp.Listener) !void {
    defer log.info("listener: successfully shut down", .{});

    var next_io_worker_index: usize = 0;

    while (true) {
        const conn = runtime.io_workers.items[0].loop.accept(listener.socket.fd, .{ .close_on_exec = true }) catch |err| switch (err) {
            error.SocketNotListening => return,
            else => return err,
        };
        errdefer conn.socket.deinit();

        const frame = try runtime.gpa.allocator.create(@Frame(Server.serveConnection));
        errdefer runtime.gpa.allocator.destroy(frame);

        try self.register(&runtime.gpa.allocator, frame, tcp.Connection.from(conn));
        errdefer self.deregister(&runtime.gpa.allocator, frame);

        frame.* = async self.serveConnection(runtime, next_io_worker_index, tcp.Connection.from(conn));
        runtime.io_workers.items[next_io_worker_index].loop.notify();

        next_io_worker_index = (next_io_worker_index + 1) % runtime.io_workers.items.len;
    }
}

fn serveConnection(self: *Server, runtime: *Runtime, io_worker_index: usize, conn: tcp.Connection) !void {
    defer {
        conn.deinit();
        suspend self.deregister(&runtime.gpa.allocator, @frame());
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

fn register(self: *Server, gpa: *mem.Allocator, frame: *@Frame(Server.serveConnection), conn: tcp.Connection) !void {
    const held = self.connections.lock.acquire();
    defer held.release();

    try self.connections.entries.put(gpa, frame, conn);
    _ = self.live_connections.count.fetchAdd(1, .Monotonic);
}

fn deregister(self: *Server, gpa: *mem.Allocator, frame: *@Frame(Server.serveConnection)) void {
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

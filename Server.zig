const std = @import("std");

const mem = std.mem;
const tcp = std.x.net.tcp;
const log = std.log.scoped(.server);

const assert = std.debug.assert;

const Runtime = @import("Runtime.zig");

const Server = @This();

connections: std.AutoArrayHashMapUnmanaged(*@Frame(Server.serveConnection), tcp.Connection) = .{},

pending: struct {
    shutdown: std.SinglyLinkedList(anyframe) = .{},
} = .{},

pub fn init() Server {
    return .{};
}

pub fn deinit(self: *Server, gpa: *mem.Allocator) void {
    self.connections.deinit(gpa);
}

pub fn shutdown(self: *Server) void {
    var it = self.connections.iterator();
    while (it.next()) |entry| {
        entry.value_ptr.client.shutdown(.recv) catch {};
    }
}

pub fn waitForShutdown(self: *Server) callconv(.Async) void {
    if (self.connections.count() > 0) {
        var waiter: std.SinglyLinkedList(anyframe).Node = .{ .data = @frame() };
        suspend self.pending.shutdown.prepend(&waiter);
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
        runtime.yield(io_worker_index, 0);

        suspend {
            conn.deinit();
            self.deregister(&runtime.gpa.allocator, @frame());
        }
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
    try self.connections.put(gpa, frame, conn);
}

fn deregister(self: *Server, gpa: *mem.Allocator, frame: *@Frame(Server.serveConnection)) void {
    assert(self.connections.swapRemove(frame));

    gpa.destroy(frame);

    if (self.connections.count() == 0) {
        while (self.pending.shutdown.popFirst()) |node| {
            resume node.data;
        }
    }
}

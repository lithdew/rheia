const std = @import("std");

const mem = std.mem;
const tcp = std.x.net.tcp;
const log = std.log.scoped(.server);

const Atomic = std.atomic.Atomic;
const Runtime = @import("Runtime.zig");

const Server = @This();

connections: std.AutoArrayHashMapUnmanaged(*@Frame(Server.serveConnection), tcp.Connection) = .{},

live_connections: struct {
    count: usize = 0,
    waiter: ?anyframe = null,
},

pub fn init() Server {
    return .{ .connections = .{}, .live_connections = .{} };
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
    if (self.live_connections.count > 0) {
        suspend self.live_connections.waiter = @frame();
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

        suspend {
            runtime.runOnWorker(io_worker_index, 0, struct {
                server_: *Server,
                gpa_: *mem.Allocator,
                frame_: *@Frame(Server.serveConnection),

                pub fn run(self_: @This()) void {
                    return self_.server_.deregister(self_.gpa_, self_.frame_);
                }
            }{ .server_ = self, .gpa_ = &runtime.gpa.allocator, .frame_ = @frame() });
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
    self.live_connections.count += 1;
}

fn deregister(self: *Server, gpa: *mem.Allocator, frame: *@Frame(Server.serveConnection)) void {
    if (!self.connections.swapRemove(frame)) {
        return;
    }
    gpa.destroy(frame);

    self.live_connections.count -= 1;
    if (self.live_connections.count > 0) {
        return;
    }

    const waiter = self.live_connections.waiter orelse return;
    self.live_connections.waiter = null;

    resume waiter;
}

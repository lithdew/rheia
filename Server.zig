const std = @import("std");

const mem = std.mem;
const tcp = std.x.net.tcp;
const log = std.log.scoped(.server);

const binary = @import("binary.zig");

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
    log.info("listening for peers on {}", .{try listener.getLocalAddress()});
    defer log.info("successfully shut down", .{});

    const loop = &runtime.workers.items[0].loop;

    var next_worker_index: usize = 0;

    while (true) {
        const conn = loop.accept(listener.socket.fd, .{ .close_on_exec = true }) catch |err| switch (err) {
            error.SocketNotListening => return,
            else => return err,
        };
        errdefer conn.socket.deinit();

        const frame = try runtime.gpa.create(@Frame(Server.serveConnection));
        errdefer runtime.gpa.destroy(frame);

        try self.register(runtime.gpa, frame, tcp.Connection.from(conn));
        errdefer self.deregister(runtime.gpa, frame);

        frame.* = async self.serveConnection(runtime, next_worker_index, tcp.Connection.from(conn));
        next_worker_index = (next_worker_index + 1) % runtime.workers.items.len;
    }
}

fn serveConnection(self: *Server, runtime: *Runtime, worker_index: usize, conn: tcp.Connection) !void {
    log.debug("new peer connected: {}", .{conn.address});
    defer log.debug("peer disconnected: {}", .{conn.address});

    const loop = &runtime.workers.items[worker_index].loop;

    runtime.yield(0, worker_index);

    defer {
        runtime.yield(worker_index, 0);

        suspend {
            conn.deinit();
            self.deregister(runtime.gpa, @frame());
        }
    }

    try conn.client.setNoDelay(true);

    var buffer = std.fifo.LinearFifo(u8, .Dynamic).init(runtime.gpa);
    defer buffer.deinit();

    while (true) {
        try buffer.ensureUnusedCapacity(@sizeOf(u32));

        while (buffer.count < @sizeOf(u32)) {
            const num_bytes_read = try loop.recv(conn.client.socket.fd, buffer.writableSlice(0), 0);
            if (num_bytes_read == 0) return error.EndOfFile;
            buffer.update(num_bytes_read);
        }

        var size: u32 = undefined;

        var size_pos: usize = 0;
        while (size_pos < @sizeOf(u32)) {
            size_pos += buffer.read(mem.asBytes(&size)[size_pos..]);
        }

        size = try binary.decode(u32, mem.asBytes(&size));
        if (size < @sizeOf(u32)) return error.MessageSizeTooSmall;
        if (size > 65536) return error.MessageSizeTooLarge;

        size -= @sizeOf(u32);

        try buffer.ensureUnusedCapacity(size);

        while (buffer.count < size) {
            const num_bytes_read = try loop.recv(conn.client.socket.fd, buffer.writableSlice(0), 0);
            if (num_bytes_read == 0) return error.EndOfFile;
            buffer.update(num_bytes_read);
        }

        const message = try runtime.gpa.alloc(u8, size);
        defer runtime.gpa.free(message); // make it errdefer after implementing message handling

        var message_pos: usize = 0;
        while (message_pos < size) {
            message_pos += buffer.read(message[message_pos..]);
        }
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

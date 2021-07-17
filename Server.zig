const std = @import("std");

const os = std.os;
const mem = std.mem;
const ip = std.x.net.ip;
const tcp = std.x.net.tcp;
const log = std.log.scoped(.server);

const binary = @import("binary.zig");

const assert = std.debug.assert;

const Loop = @import("Loop.zig");
const Packet = @import("Packet.zig");
const Worker = @import("Worker.zig");
const Runtime = @import("Runtime.zig");

const Server = @This();

pub const Connection = struct {
    worker_index: usize,
    client: tcp.Client,
    address: ip.Address,
    frame: @Frame(Server.serveConnection),

    writer: ?*Worker.Task,
    queue: std.SinglyLinkedList([]const u8),
};

connections: std.AutoArrayHashMapUnmanaged(*Server.Connection, void) = .{},

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
        entry.key_ptr.*.client.shutdown(.recv) catch {};
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

        const server_conn = try runtime.gpa.create(Server.Connection);
        errdefer runtime.gpa.destroy(server_conn);

        try self.register(runtime.gpa, server_conn);
        errdefer self.deregister(runtime.gpa, server_conn);

        server_conn.worker_index = next_worker_index;
        defer next_worker_index = (next_worker_index + 1) % runtime.workers.items.len;

        server_conn.client = tcp.Client.from(conn.socket);
        server_conn.address = ip.Address.from(conn.address);

        server_conn.writer = null;
        server_conn.queue = .{};

        server_conn.frame = async self.serveConnection(runtime, server_conn);
    }
}

fn serveConnection(self: *Server, runtime: *Runtime, conn: *Server.Connection) !void {
    log.debug("new peer connected: {}", .{conn.address});
    defer log.debug("peer disconnected: {}", .{conn.address});

    defer {
        while (conn.queue.popFirst()) |node| {
            runtime.gpa.destroy(node);
        }

        suspend {
            conn.client.deinit();
            self.deregister(runtime.gpa, conn);
        }
    }

    runtime.yield(0, conn.worker_index);
    defer runtime.yield(conn.worker_index, 0);

    try conn.client.setNoDelay(true);

    var writer_done = false;
    var writer_frame = async self.runWriteLoop(runtime, conn, &writer_done);
    var reader_frame = async self.runReadLoop(runtime, conn);

    await reader_frame catch {};

    writer_done = true;
    if (conn.writer) |writer| {
        conn.writer = null;
        runtime.schedule(conn.worker_index, conn.worker_index, writer);
    }

    await writer_frame catch {};
}

fn runReadLoop(_: *Server, runtime: *Runtime, conn: *Server.Connection) !void {
    const loop = &runtime.workers.items[conn.worker_index].loop;

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

        const packet = try Packet.unmarshal(message);

        switch (packet.get(.type)) {
            .command => switch (packet.get(.tag)) {
                .ping => {
                    var buf = std.ArrayList(u8).init(runtime.gpa);
                    errdefer buf.deinit();

                    const node_data = try binary.Buffer.from(&buf).allocate(@sizeOf(std.SinglyLinkedList([]const u8).Node));
                    const node = @ptrCast(*std.SinglyLinkedList([]const u8).Node, @alignCast(@alignOf(*std.SinglyLinkedList([]const u8).Node), node_data.ptr()));

                    var size_data = try binary.allocate(node_data.sliceFromEnd(), u32);
                    var body_data = try Packet.append(size_data.sliceFromEnd(), .{ .nonce = packet.get(.nonce), .@"type" = .command, .tag = .ping });
                    node.* = .{ .data = size_data.ptr()[0 .. size_data.len + body_data.len] };

                    size_data = binary.writeAssumeCapacity(node_data.sliceFromEnd(), @intCast(u32, size_data.len + body_data.len));

                    conn.queue.prepend(node);
                    if (conn.writer) |writer| {
                        conn.writer = null;
                        runtime.schedule(conn.worker_index, conn.worker_index, writer);
                    }
                },
                else => {},
            },
            else => {},
        }
    }
}

fn runWriteLoop(_: *Server, runtime: *Runtime, conn: *Server.Connection, writer_done: *const bool) !void {
    const loop = &runtime.workers.items[conn.worker_index].loop;

    var buffer: [65536]u8 = undefined;
    var pos: usize = 0;

    while (true) {
        if (conn.queue.first == null) {
            if (writer_done.*) return error.Closed;
            var task: Worker.Task = .{ .value = @frame() };
            suspend conn.writer = &task;
            continue;
        }

        while (conn.queue.popFirst()) |node| {
            defer runtime.gpa.destroy(node);

            if (node.data.len >= buffer[pos..].len) {
                // If a queued message cannot fit into the buffer, do a dedicated send() on
                // the message rather than attempt to have it fit inside the buffer.

                if (node.data.len > buffer.len) {
                    @setCold(true);
                    try writeAll(loop, conn.client, node.data);
                    continue;
                }

                try writeAll(loop, conn.client, buffer[0..pos]);
                pos = 0;
            }

            mem.copy(u8, buffer[pos..], node.data);
            pos += node.data.len;
        }

        try writeAll(loop, conn.client, buffer[0..pos]);
        pos = 0;
    }
}

fn writeAll(loop: *Loop, client: tcp.Client, buffer: []const u8) !void {
    var index: usize = 0;
    while (index < buffer.len) {
        index += try loop.send(client.socket.fd, buffer[index..], os.MSG_NOSIGNAL);
    }
}

fn register(self: *Server, gpa: *mem.Allocator, conn: *Server.Connection) !void {
    try self.connections.put(gpa, conn, {});
}

fn deregister(self: *Server, gpa: *mem.Allocator, conn: *Server.Connection) void {
    assert(self.connections.swapRemove(conn));
    gpa.destroy(conn);

    if (self.connections.count() == 0) {
        while (self.pending.shutdown.popFirst()) |node| {
            resume node.data;
        }
    }
}

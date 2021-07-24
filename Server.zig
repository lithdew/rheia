const std = @import("std");

const os = std.os;
const mem = std.mem;
const ip = std.x.net.ip;
const tcp = std.x.net.tcp;
const log = std.log.scoped(.server);
const sync = @import("sync.zig");
const runtime = @import("runtime.zig");

const binary = @import("binary.zig");

const assert = std.debug.assert;

const Packet = @import("Packet.zig");

const SinglyLinkedList = @import("intrusive.zig").SinglyLinkedList;

const Server = @This();

pub const Waiter = struct {
    next: ?*Server.Waiter = null,
    worker_id: usize,
    task: runtime.Task,
};

pub const Connection = struct {
    worker_id: usize,
    client: tcp.Client,
    address: ip.Address,
    frame: @Frame(Server.serveConnection),

    done: bool,
    writer: ?*runtime.Task,
    queuer: ?*runtime.Task,

    queue: std.fifo.LinearFifo(u8, .Dynamic),
};

connections: std.AutoHashMapUnmanaged(*Server.Connection, void) = .{},

pending: struct {
    shutdown: SinglyLinkedList(Server.Waiter, .next) = .{},
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

pub fn join(self: *Server) callconv(.Async) void {
    if (self.connections.count() > 0) {
        var waiter: Server.Waiter = .{
            .worker_id = runtime.getCurrentWorkerId(),
            .task = .{ .frame = @frame() },
        };

        suspend {
            self.pending.shutdown.prepend(&waiter);
        }
    }
}

pub fn serve(self: *Server, gpa: *mem.Allocator, listener: tcp.Listener) !void {
    const address = try listener.getLocalAddress();

    log.info("listening for peers on {}", .{address});
    defer log.info("stopped listening for peers on {}", .{address});

    var next_worker_id: usize = 0;
    var request: runtime.Request = .{};

    while (true) {
        const conn = runtime.accept(&request, listener.socket.fd, .{ .close_on_exec = true, .nonblocking = true }) catch |err| switch (err) {
            error.SocketNotListening => return,
            else => return err,
        };
        errdefer conn.socket.deinit();

        const server_conn = try gpa.create(Server.Connection);
        errdefer gpa.destroy(server_conn);

        try self.register(gpa, server_conn);
        errdefer self.deregister(gpa, server_conn);

        server_conn.worker_id = next_worker_id;
        defer next_worker_id = (next_worker_id + 1) % runtime.getNumWorkers();

        server_conn.client = tcp.Client.from(conn.socket);
        server_conn.address = ip.Address.from(conn.address);

        server_conn.done = false;
        server_conn.writer = null;
        server_conn.queuer = null;

        server_conn.queue = std.fifo.LinearFifo(u8, .Dynamic).init(gpa);

        server_conn.frame = async self.serveConnection(gpa, server_conn);
    }
}

fn serveConnection(self: *Server, gpa: *mem.Allocator, conn: *Server.Connection) !void {
    defer {
        conn.queue.deinit();
        conn.client.deinit();

        suspend self.deregister(gpa, conn);
    }

    log.debug("new peer connected: {}", .{conn.address});
    defer log.debug("peer disconnected: {}", .{conn.address});

    runtime.yield(conn.worker_id);
    defer runtime.yield(0);

    try conn.client.setNoDelay(true);

    var writer_frame = async self.runWriteLoop(conn);
    var reader_frame = async self.runReadLoop(gpa, conn);

    await reader_frame catch {};
    await writer_frame catch {};
}

fn runReadLoop(_: *Server, gpa: *mem.Allocator, conn: *Server.Connection) !void {
    defer {
        conn.done = true;
        if (conn.writer) |waiter| {
            conn.writer = null;
            runtime.schedule(waiter);
        }
    }

    var buffer = std.fifo.LinearFifo(u8, .Dynamic).init(gpa);
    defer buffer.deinit();

    var buf = std.ArrayList(u8).init(gpa);
    defer buf.deinit();

    var task: runtime.Task = .{ .frame = @frame() };
    var request: runtime.Request = .{};

    while (true) {
        while (buffer.count < @sizeOf(u32)) {
            const num_bytes_read = try runtime.recv(&request, conn.client.socket.fd, try buffer.writableWithSize(65536), 0);
            if (num_bytes_read == 0) return error.EndOfFile;
            buffer.update(num_bytes_read);
        }

        var size: u32 = undefined;
        try buffer.reader().readNoEof(mem.asBytes(&size));

        size = try binary.decode(u32, mem.asBytes(&size));
        if (size < @sizeOf(u32)) return error.MessageSizeTooSmall;
        if (size > 65536) return error.MessageSizeTooLarge;

        size -= @sizeOf(u32);

        while (buffer.count < size) {
            const num_bytes_read = try runtime.recv(&request, conn.client.socket.fd, try buffer.writableWithSize(65536), 0);
            if (num_bytes_read == 0) return error.EndOfFile;
            buffer.update(num_bytes_read);
        }

        const message = try gpa.alloc(u8, size);
        defer gpa.free(message);

        try buffer.reader().readNoEof(message);

        const packet = try Packet.unmarshal(message);

        switch (packet.get(.type)) {
            .request => switch (packet.get(.tag)) {
                .ping => {
                    buf.clearRetainingCapacity();

                    var size_data = try binary.allocate(binary.Buffer.from(&buf), u32);
                    var body_data = try Packet.append(size_data.sliceFromEnd(), .{ .nonce = packet.get(.nonce), .@"type" = .response, .tag = .ping });
                    size_data = binary.writeAssumeCapacity(size_data.sliceFromStart(), @intCast(u32, size_data.len + body_data.len));

                    while (buf.items.len + conn.queue.count > 1 * 1024 * 1024) {
                        if (conn.done) return error.Closed;
                        suspend conn.queuer = &task;
                    }

                    try conn.queue.writer().writeAll(buf.items);

                    if (conn.writer) |waiter| {
                        conn.writer = null;
                        runtime.schedule(waiter);
                    }
                },
                else => {},
            },
            else => {},
        }
    }
}

fn runWriteLoop(_: *Server, conn: *Server.Connection) !void {
    defer {
        conn.done = true;
        if (conn.queuer) |queuer| {
            conn.queuer = null;
            runtime.schedule(queuer);
        }
    }

    var buffer: [65536]u8 = undefined;

    var task: runtime.Task = .{ .frame = @frame() };
    var request: runtime.Request = .{};

    while (true) {
        if (conn.queue.count == 0) {
            if (conn.done) return error.Closed;
            suspend conn.writer = &task;
            continue;
        }

        while (conn.queue.count > 0) {
            try writeAll(&request, conn.client, buffer[0..try conn.queue.reader().readAll(&buffer)]);
        }

        if (conn.queuer) |waiter| {
            conn.queuer = null;
            runtime.schedule(waiter);
        }
    }
}

fn writeAll(request: *runtime.Request, client: tcp.Client, buffer: []const u8) !void {
    var index: usize = 0;
    while (index < buffer.len) {
        index += try runtime.send(request, client.socket.fd, buffer[index..], os.MSG_NOSIGNAL);
    }
}

fn register(self: *Server, gpa: *mem.Allocator, conn: *Server.Connection) !void {
    try self.connections.put(gpa, conn, {});
}

fn deregister(self: *Server, gpa: *mem.Allocator, conn: *Server.Connection) void {
    assert(self.connections.remove(conn));

    gpa.destroy(conn);

    if (self.connections.count() > 0) {
        return;
    }

    while (self.pending.shutdown.popFirst()) |waiter| {
        runtime.scheduleTo(waiter.worker_id, &waiter.task);
    }
}

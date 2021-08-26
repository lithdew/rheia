const std = @import("std");
const net = @import("net.zig");
const runtime = @import("runtime.zig");

const mem = std.mem;
const tcp = std.x.net.tcp;

const Context = runtime.Context;

const assert = std.debug.assert;

const http = @This();

pub usingnamespace @import("http/http.zig");

pub fn Listener(comptime Handler: type) type {
    return struct {
        const log = std.log.scoped(.http_listener);

        const Self = @This();

        handler: *Handler,

        pub fn init(handler: *Handler) Self {
            return Self{ .handler = handler };
        }

        pub fn serve(ctx: *Context, gpa: *mem.Allocator, net_listener: *net.Listener(Self), listener: tcp.Listener) !void {
            const bind_address = try listener.getLocalAddress();

            log.info("listening for requests on: {}", .{bind_address});
            defer log.info("stopped listening for requests: {}", .{bind_address});

            return net_listener.serve(ctx, gpa, listener);
        }

        pub fn runReadLoop(self: *Self, ctx: *Context, gpa: *mem.Allocator, conn: *net.Listener(Self).Connection) !void {
            var stream: runtime.Stream = .{ .socket = conn.client.socket, .context = ctx };
            var reader = stream.reader();

            var buffer = std.fifo.LinearFifo(u8, .Dynamic).init(gpa);
            defer buffer.deinit();

            errdefer |err| log.warn("error while handling request: {}", .{err});

            while (true) {
                const num_bytes_read: usize = buffer: {
                    var ret_cnt: usize = 0;
                    while (true) {
                        const buf = try buffer.writableWithSize(65536);
                        const num_bytes = try reader.read(buf);
                        if (num_bytes == 0) return;
                        buffer.update(num_bytes);

                        var index: usize = 0;
                        while (index < buf.len) : (index += 1) {
                            if (buf[index] == '\r') {
                                if (index + 1 >= buf.len) {
                                    break;
                                }
                                if (buf[index + 1] != '\n') {
                                    break;
                                }
                                index +%= 1;
                                ret_cnt += 1;
                            } else if (buf[index] == '\n') {
                                ret_cnt += 1;
                            } else {
                                ret_cnt = 0;
                            }
                            if (ret_cnt == 2) {
                                break :buffer index + 1;
                            }
                        }
                    }
                };

                const frame = try gpa.alloc(u8, num_bytes_read);
                defer gpa.free(frame);

                try buffer.reader().readNoEof(frame);

                var headers: [100]http.Header = undefined;
                var request: http.Request = .{ .headers = &headers };
                assert((try http.readRequest(frame, &request, 0)) == num_bytes_read);

                while (conn.buffer.items.len > 65536) {
                    try conn.write_parker.park(ctx);
                }

                try self.handler.handleHttpRequest(ctx, gpa, request, buffer.reader(), conn.buffer.writer());
                if (conn.buffer.items.len > 0) {
                    conn.writer_parker.notify({});
                }
            }
        }

        pub fn runWriteLoop(self: *Self, ctx: *Context, gpa: *mem.Allocator, conn: *net.Listener(Self).Connection) !void {
            _ = self;
            _ = gpa;

            var stream: runtime.Stream = .{ .socket = conn.client.socket, .context = ctx };
            var writer = stream.writer();

            while (true) {
                while (conn.buffer.items.len == 0) {
                    try conn.writer_parker.park(ctx);
                }

                const buffer = conn.buffer.toOwnedSlice();
                defer gpa.free(buffer);

                try writer.writeAll(buffer);
                conn.write_parker.notify({});
            }
        }
    };
}

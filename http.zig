const std = @import("std");
const net = @import("net.zig");
const runtime = @import("runtime.zig");

const fmt = std.fmt;
const mem = std.mem;
const tcp = std.x.net.tcp;
const ascii = std.ascii;
const json = std.json;

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

        pub fn serve(ctx: *Context, gpa: mem.Allocator, net_listener: *net.Listener(Self), listener: tcp.Listener) !void {
            const bind_address = try listener.getLocalAddress();

            log.info("listening for requests on: {}", .{bind_address});
            defer log.info("stopped listening for requests: {}", .{bind_address});

            return net_listener.serve(ctx, gpa, listener);
        }

        pub fn runReadLoop(self: *Self, ctx: *Context, gpa: mem.Allocator, conn: *net.Listener(Self).Connection) !void {
            var buffer = std.fifo.LinearFifo(u8, .Dynamic).init(gpa);
            defer buffer.deinit();

            errdefer |err| log.warn("error while handling request: {}", .{err});

            while (true) {
                const num_bytes_read: usize = buffer: {
                    var ret_cnt: usize = 0;
                    while (true) {
                        const buf = try buffer.writableWithSize(65536);
                        const num_bytes = try runtime.recv(ctx, conn.client.socket, buf, 0);
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
                if ((try http.readRequest(frame, &request, 0)) != num_bytes_read) {
                    return error.ShortBuffer;
                }

                while (conn.buffer.items.len > 65536) {
                    try conn.write_parker.park(ctx);
                }

                self.handler.handleHttpRequest(ctx, gpa, request, buffer.reader(), conn.buffer.writer()) catch |err| if (conn.buffer.items.len == 0) {
                    var buf: [1024]u8 = undefined;

                    // make error name lower-cased

                    var error_name_len: usize = 0;
                    for (@errorName(err)) |character, i| {
                        if (i != 0 and ascii.isUpper(character)) {
                            buf[error_name_len] = '_';
                            error_name_len += 1;
                        }

                        buf[error_name_len] = ascii.toLower(character);
                        error_name_len += 1;
                    }

                    // create default error response json

                    var body = std.ArrayList(u8).init(gpa);
                    defer body.deinit();

                    var stream = json.writeStream(body.writer(), 128);

                    try stream.beginObject();
                    try stream.objectField("error");
                    try stream.emitString(buf[0..error_name_len]);
                    try stream.endObject();

                    // send default error response

                    const response: http.Response = .{
                        .status_code = 500,
                        .message = "Internal Server Error",
                        .headers = &[_]http.Header{
                            .{ .name = "Content-Type", .value = "application/json" },
                            .{ .name = "Content-Length", .value = fmt.bufPrintIntToSlice(&buf, body.items.len, 10, .lower, .{}) },
                        },
                        .num_headers = 2,
                    };

                    try conn.buffer.writer().print("{}", .{response});
                    try conn.buffer.writer().print("{s}", .{body.items});
                };
                if (conn.buffer.items.len > 0) {
                    conn.writer_parker.notify({});
                }
            }
        }

        pub fn runWriteLoop(self: *Self, ctx: *Context, gpa: mem.Allocator, conn: *net.Listener(Self).Connection) !void {
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

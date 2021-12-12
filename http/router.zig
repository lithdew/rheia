const std = @import("std");
const http = @import("http.zig");
const trie = @import("trie.zig");
const runtime = @import("../runtime.zig");

const fmt = std.fmt;
const mem = std.mem;
const math = std.math;
const meta = std.meta;

const Uri = @import("uri.zig").Uri;
const Context = runtime.Context;

pub const Route = struct {
    method: http.Method,
    path: []const u8,
    handler: anytype,
};

pub const Param = struct {
    key: []const u8,
    value: []const u8,
};

pub fn handle(comptime method: http.Method, comptime path: []const u8, comptime handler: anytype) Route {
    return .{ .method = method, .path = path, .handler = handler };
}

pub fn get(comptime path: []const u8, comptime handler: anytype) Route {
    return handle(.get, path, handler);
}

pub fn post(comptime path: []const u8, comptime handler: anytype) Route {
    return handle(.post, path, handler);
}

pub fn build(comptime Handler: type, routes: anytype) type {
    comptime var roots: [@typeInfo(http.Method).Enum.fields.len - 1]trie.Node(usize) = undefined;
    inline for (roots) |*root| root.* = .{};

    comptime var max_params: usize = 0;
    inline for (routes) |route, i| {
        roots[@enumToInt(route.method)].put(route.path, i);
        max_params = math.max(max_params, trie.countParams(route.path));
    }

    return struct {
        pub fn handleHttpRequest(handler: Handler, ctx: *Context, gpa: mem.Allocator, request: http.Request, reader: anytype, writer: anytype) !void {
            const method = http.Method.from(request.method);
            if (method == .unknown) {
                return error.UnknownMethod;
            }

            var uri = try Uri.parse(request.path, true);

            var params: [max_params]Param = undefined;
            var num_params: usize = 0;

            var it: struct {
                params: *[max_params]Param,
                num_params: *usize,

                pub fn next(self: @This(), key: []const u8, value: []const u8) void {
                    if (max_params > 0) {
                        self.params[self.num_params.*].key = key;
                        self.params[self.num_params.*].value = value;
                        self.num_params.* += 1;
                    }
                }
            } = .{ .params = &params, .num_params = &num_params };

            switch (roots[@enumToInt(method)].get(uri.path, it)) {
                .found => |index| {
                    inline for (routes) |route, i| {
                        if (i == index) {
                            return route.handler(handler, ctx, gpa, request, reader, writer, params[0..num_params]);
                        }
                    }
                },
                .not_found, .trailing_slash_redirect => {
                    const response: http.Response = .{
                        .status_code = 404,
                        .message = "Not Found",
                        .headers = &[_]http.Header{.{
                            .name = "Content-Length",
                            .value = fmt.comptimePrint("{d}", .{"404 not found".len}),
                        }},
                        .num_headers = 1,
                    };

                    try writer.print("{}", .{response});
                    try writer.print("404 not found", .{});
                },
                // .trailing_slash_redirect => {
                //     const status_code: usize = if (method == .get) 301 else 308;
                //     const status_text: []const u8 = if (method == .get) "Moved Permanently" else "Permanent Redirect";

                //     if (uri.path.len > 1 and uri.path[uri.path.len - 1] == '/') {
                //         uri.path = uri.path[0 .. uri.path.len - 1];

                //         const new_uri = try fmt.allocPrint(gpa, "{}", .{uri});
                //         defer gpa.free(new_uri);

                //         const response: http.Response = .{
                //             .status_code = status_code,
                //             .message = status_text,
                //             .headers = &[_]http.Header{.{
                //                 .name = "Location",
                //                 .value = new_uri,
                //             }},
                //             .num_headers = 1,
                //         };

                //         try writer.print("{}", .{response});
                //     } else {
                //         const new_path = try gpa.alloc(u8, uri.path.len + 1);
                //         defer gpa.free(new_path);

                //         mem.copy(u8, new_path, uri.path);
                //         new_path[uri.path.len] = '/';

                //         uri.path = new_path;

                //         const new_uri = try fmt.allocPrint(gpa, "{}", .{uri});
                //         defer gpa.free(new_uri);

                //         const response: http.Response = .{
                //             .status_code = status_code,
                //             .message = status_text,
                //             .headers = &[_]http.Header{.{
                //                 .name = "Location",
                //                 .value = new_uri,
                //             }},
                //             .num_headers = 1,
                //         };

                //         try writer.print("{}", .{response});
                //     }
                // },
            }
        }
    };
}

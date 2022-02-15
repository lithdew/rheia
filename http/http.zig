// MIT License

// Copyright (c) 2009-2014 Kazuho Oku, Tokuhiro Matsuno, Daisuke Murase,
//                         Shigeo Mitsunari
// Copyright (c) 2021 Kenta Iwasaki

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

const std = @import("std");
const builtin = @import("builtin");

const fmt = std.fmt;
const mem = std.mem;
const meta = std.meta;
const testing = std.testing;

const assert = std.debug.assert;

const CaseInsensitiveStringMap = @import("comptime.zig").CaseInsensitiveStringMap;

pub const router = @import("router.zig");
pub const Uri = @import("uri.zig").Uri;

pub const Method = enum {
    const map = CaseInsensitiveStringMap(Method, .{
        .{ "GET", .get },
        .{ "HEAD", .head },
        .{ "POST", .post },
        .{ "PUT", .put },
        .{ "DELETE", .delete },
        .{ "CONNECT", .connect },
        .{ "OPTIONS", .options },
        .{ "TRACE", .trace },
        .{ "PATH", .path },
    });

    get,
    head,
    post,
    put,
    delete,
    connect,
    options,
    trace,
    path,
    unknown,

    pub fn into(self: Method) []const u8 {
        return map.get(self) orelse "UNKNOWN";
    }

    pub fn from(method: []const u8) Method {
        return map.parse(method) orelse Method.unknown;
    }

    pub fn format(self: Method, comptime layout: []const u8, options: fmt.FormatOptions, writer: anytype) !void {
        _ = layout;
        _ = options;
        try fmt.format(writer, "{s}", .{self.into()});
    }
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,

    pub fn format(self: Header, comptime layout: []const u8, options: fmt.FormatOptions, writer: anytype) !void {
        _ = layout;
        _ = options;

        if (self.name.len == 0) {
            try fmt.format(writer, " {s}", .{self.value});
        } else {
            try fmt.format(writer, "{s}: {s}", .{ self.name, self.value });
        }
    }
};

pub fn parseHeaders(buf_const: [*]const u8, buf_end: [*]const u8, headers: []Header, num_headers: *usize) ![*]const u8 {
    var buf = buf_const;
    while (true) : (num_headers.* += 1) {
        try checkEndOfStream(buf, buf_end);
        if (buf[0] == '\r') {
            buf += 1;
            buf = try expectCharacterNoEof(buf, buf_end, '\n');
            break;
        } else if (buf[0] == '\n') {
            buf += 1;
            break;
        }
        if (num_headers.* == headers.len) {
            return error.ShortBuffer;
        }
        if (num_headers.* == 0 or (buf[0] != ' ' and buf[0] != '\t')) {
            // Parse name, but do not discard SP before colon.
            // http://www.mozilla.org/security/announce/2006/mfsa2006-33.html
            buf = try parseToken(buf, buf_end, &headers[num_headers.*].name, ':');
            if (headers[num_headers.*].name.len == 0) {
                return error.EmptyName;
            }
            buf += 1;
            while (true) : (buf += 1) {
                try checkEndOfStream(buf, buf_end);
                if (buf[0] != ' ' and buf[0] != '\t') {
                    break;
                }
            }
        } else {
            headers[num_headers.*].name = &[_]u8{};
        }
        var value: []const u8 = undefined;
        buf = try getTokenToEndOfLine(buf, buf_end, &value);

        // Remove trailing SPs and HTABs.
        var value_end = value.ptr + value.len;
        while (value.ptr != value_end) : (value_end -= 1) {
            const character = (value_end - 1)[0];
            if (character != ' ' and character != '\t') {
                break;
            }
        }
        headers[num_headers.*].value.ptr = value.ptr;
        headers[num_headers.*].value.len = @ptrToInt(value_end) - @ptrToInt(value.ptr);
    }
    return buf;
}

pub fn readHeaders(buf: []const u8, headers: []Header, num_headers: *usize, last_len: usize) !usize {
    var buf_start = buf.ptr;
    var buf_end = buf.ptr + buf.len;

    num_headers.* = 0;

    // Check if the headers are complete. This is a fast
    // countermeasure againt Slowloris DoS attacks.
    if (last_len != 0) {
        buf_start = try isComplete(buf_start, buf_end, last_len);
    }

    buf_start = try parseHeaders(buf_start, buf_end, headers, num_headers);

    return @ptrToInt(buf_start) - @ptrToInt(buf.ptr);
}

pub const Request = struct {
    method: []const u8 = &[_]u8{},
    path: []const u8 = &[_]u8{},
    minor_version: usize = 1,
    headers: []Header = &[_]Header{},
    num_headers: usize = 0,

    pub fn getHeaders(self: Request) []const Header {
        return self.headers[0..self.num_headers];
    }

    pub fn format(self: Request, comptime layout: []const u8, options: fmt.FormatOptions, writer: anytype) !void {
        _ = layout;
        _ = options;
        try fmt.format(writer, "{s} {s} HTTP/1.{d}\r\n", .{ self.method, self.path, self.minor_version });
        for (self.headers[0..self.num_headers]) |header| {
            try fmt.format(writer, "{}\r\n", .{header});
        }
        try fmt.format(writer, "\r\n", .{});
    }
};

pub fn parseRequest(buf_const: [*]const u8, buf_end: [*]const u8, request: *Request) ![*]const u8 {
    var buf = buf_const;

    // Skip first empty line (some clients add CRLF after POST content).
    try checkEndOfStream(buf, buf_end);
    if (buf[0] == '\r') {
        buf += 1;
        buf = try expectCharacterNoEof(buf, buf_end, '\n');
    } else if (buf[0] == '\n') {
        buf += 1;
    }

    // Parse request line.
    buf = try parseToken(buf, buf_end, &request.method, ' ');
    while (true) {
        buf += 1;
        try checkEndOfStream(buf, buf_end);
        if (buf[0] != ' ') {
            break;
        }
    }
    buf = try advanceToken(buf, buf_end, &request.path);
    while (true) {
        buf += 1;
        try checkEndOfStream(buf, buf_end);
        if (buf[0] != ' ') {
            break;
        }
    }
    if (request.method.len == 0 or request.path.len == 0) {
        return error.MethodOrPathEmpty;
    }
    buf = try parseHttpVersion(buf, buf_end, &request.minor_version);
    if (buf[0] == '\r') {
        buf += 1;
        buf = try expectCharacterNoEof(buf, buf_end, '\n');
    } else if (buf[0] == '\n') {
        buf += 1;
    } else {
        return error.UnexpectedEndOfLineCharacter;
    }

    return try parseHeaders(buf, buf_end, request.headers, &request.num_headers);
}

pub fn readRequest(buf: []const u8, request: *Request, last_len: usize) !usize {
    var buf_start = buf.ptr;
    var buf_end = buf.ptr + buf.len;

    request.* = .{ .headers = request.headers };

    // Check if the request is complete. This is a fast
    // countermeasure againt Slowloris DoS attacks.
    if (last_len != 0) {
        buf_start = try isComplete(buf_start, buf_end, last_len);
    }

    buf_start = try parseRequest(buf_start, buf_end, request);

    return @ptrToInt(buf_start) - @ptrToInt(buf.ptr);
}

pub const Response = struct {
    minor_version: usize = 1,
    status_code: usize = 0,
    message: []const u8 = &[_]u8{},
    headers: []Header = &[_]Header{},
    num_headers: usize = 0,

    pub fn getHeaders(self: Response) []const Header {
        return self.headers[0..self.num_headers];
    }

    pub fn format(self: Response, comptime layout: []const u8, options: fmt.FormatOptions, writer: anytype) !void {
        _ = layout;
        _ = options;
        try fmt.format(writer, "HTTP/1.{d} {d} {s}\r\n", .{ self.minor_version, self.status_code, self.message });
        for (self.headers[0..self.num_headers]) |header| {
            try fmt.format(writer, "{}\r\n", .{header});
        }
        try fmt.format(writer, "\r\n", .{});
    }
};

pub fn parseResponse(buf_const: [*]const u8, buf_end: [*]const u8, response: *Response) ![*]const u8 {
    // Parse "HTTP/1.x".
    var buf = try parseHttpVersion(buf_const, buf_end, &response.minor_version);

    // Skip space.
    if (buf[0] != ' ') {
        return error.UnexpectedCharacter;
    }

    while (true) {
        buf += 1;
        try checkEndOfStream(buf, buf_end);
        if (buf[0] != ' ') {
            break;
        }
    }

    // Parse status code; we want at least [:digit:][:digit:][:digit:]<other char> to try to parse.
    if (@ptrToInt(buf_end) - @ptrToInt(buf) < 4) {
        return error.EndOfStream;
    }

    buf = try parseInt3(buf, &response.status_code);

    // Get message including preceding space.
    buf = try getTokenToEndOfLine(buf, buf_end, &response.message);
    if (response.message.len != 0 and response.message[0] == ' ') {
        // Remove preceding space. Successful return from `getTokenToEndOfLine` guarantees that we would hit something other than SP
        // before running past the end of the given buffer.
        while (true) {
            response.message.ptr += 1;
            response.message.len -= 1;
            if (response.message[0] != ' ') {
                break;
            }
        }
    } else {
        return error.UnexpectedTextFoundAfterStatusCode;
    }
    return try parseHeaders(buf, buf_end, response.headers, &response.num_headers);
}

pub fn readResponse(buf: []const u8, response: *Response, last_len: usize) !usize {
    var buf_start = buf.ptr;
    var buf_end = buf.ptr + buf.len;

    response.* = .{ .headers = response.headers };

    // Check if the response is complete. This is a fast
    // countermeasure againt Slowloris DoS attacks.
    if (last_len != 0) {
        buf_start = try isComplete(buf_start, buf_end, last_len);
    }

    buf_start = try parseResponse(buf_start, buf_end, response);

    return @ptrToInt(buf_start) - @ptrToInt(buf.ptr);
}

const token_char_map = [256]u1{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x00
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x10
    0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, // 0x20
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, // 0x30
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x40
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, // 0x50
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x60
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, // 0x70
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x80
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x90
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xa0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xb0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xc0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xd0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xe0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xf0
};

fn findCharacter(buf_const: [*]const u8, buf_end: [*]const u8, ranges: [*]const u8, ranges_len: usize, found: *bool) [*]const u8 {
    found.* = false;

    var buf = buf_const;
    if (comptime std.Target.x86.featureSetHas(builtin.target.cpu.features, .sse4_2)) {
        const Intrinsic = struct {
            extern fn @"llvm.x86.sse42.pcmpestri128"(meta.Vector(16, i8), i32, meta.Vector(16, i8), i32, u8) i32;
        };

        if (@ptrToInt(buf_end) - @ptrToInt(buf) >= 16) {
            const ranges16 = @as(meta.Vector(16, u8), ranges[0..16].*);

            var left = (@ptrToInt(buf_end) - @ptrToInt(buf)) & ~@as(usize, 16 - 1);
            while (true) {
                const buf16 = @as(meta.Vector(16, u8), buf[0..16].*);

                const r = Intrinsic.@"llvm.x86.sse42.pcmpestri128"(
                    @bitCast(meta.Vector(16, i8), ranges16),
                    @intCast(i32, ranges_len),
                    @bitCast(meta.Vector(16, i8), buf16),
                    16,
                    4,
                );
                if (r != 16) {
                    buf += @intCast(usize, r);
                    found.* = true;
                    break;
                }

                buf += 16;
                left -= 16;

                if (left == 0) {
                    @setCold(true);
                    break;
                }
            }
        }
    }

    return buf;
}

inline fn checkEndOfStream(buf: [*]const u8, buf_end: [*]const u8) !void {
    if (buf == buf_end) {
        return error.EndOfStream;
    }
}

inline fn expectCharacter(buf: [*]const u8, comptime character: u8) ![*]const u8 {
    if (buf[0] != character) {
        return error.UnexpectedCharacter;
    }
    return buf + 1;
}

inline fn expectCharacterNoEof(buf_const: [*]const u8, buf_end: [*]const u8, comptime character: u8) ![*]const u8 {
    try checkEndOfStream(buf_const, buf_end);
    return try expectCharacter(buf_const, character);
}

inline fn advanceToken(buf_const: [*]const u8, buf_end: [*]const u8, token: *[]const u8) ![*]const u8 {
    const ranges: [*]const u8 = "\x00 \x7f\x7f";

    const token_start = buf_const;

    var found: bool = undefined;
    var buf = findCharacter(buf_const, buf_end, ranges, 4, &found);
    if (!found) {
        try checkEndOfStream(buf, buf_end);
    }
    while (true) {
        if (buf[0] == ' ') {
            break;
        } else if (!isPrintableAscii(buf[0])) {
            @setCold(true);
            if (buf[0] < ' ' or buf[0] == '\x7f') {
                return error.UnexpectedCharacter;
            }
        }
        buf += 1;
        try checkEndOfStream(buf, buf_const);
    }
    token.ptr = token_start;
    token.len = @ptrToInt(buf) - @ptrToInt(token_start);
    return buf;
}

inline fn isPrintableAscii(character: u8) bool {
    return character -% ' ' < '_';
}

fn getTokenToEndOfLine(buf_const: [*]const u8, buf_end: [*]const u8, token: *[]const u8) ![*]const u8 {
    const ranges: [*]const u8 =
        "\x00\x08" ++ // allow HT
        "\n\x1f" ++ // allow SP and up to but not including DEL
        "\x7f\x7f" ++ // allow chars w. MSB set
        [_]u8{0} ** 10;

    const token_start = buf_const;

    var found: bool = undefined;
    var buf = findCharacter(buf_const, buf_end, ranges, 6, &found);
    if (found) {
        if (buf[0] == '\r') {
            buf += 1;
            buf = try expectCharacterNoEof(buf, buf_end, '\n');
            token.len = @ptrToInt(buf) - 2 - @ptrToInt(token_start);
        } else if (buf[0] == '\n') {
            token.len = @ptrToInt(buf) - @ptrToInt(token_start);
            buf += 1;
        } else {
            return error.UnexpectedCharacter;
        }
        token.ptr = token_start;
        return buf;
    }

    while (true) : (buf += 1) {
        try checkEndOfStream(buf, buf_end);
        if (!isPrintableAscii(buf[0])) {
            @setCold(true);
            if ((buf[0] < ' ' and buf[0] != '\t') or buf[0] == '\x7f') {
                break;
            }
        }
    }

    if (buf[0] == '\r') {
        buf += 1;
        buf = try expectCharacterNoEof(buf, buf_end, '\n');
        token.len = @ptrToInt(buf) - 2 - @ptrToInt(token_start);
    } else if (buf[0] == '\n') {
        token.len = @ptrToInt(buf) - @ptrToInt(token_start);
        buf += 1;
    } else {
        return error.UnexpectedCharacter;
    }
    token.ptr = token_start;
    return buf;
}

fn isComplete(buf_const: [*]const u8, buf_end: [*]const u8, last_len: usize) ![*]const u8 {
    var buf = if (last_len < 3) buf_const else buf_const + last_len - 3;
    var ret_cnt: usize = 0;
    while (true) {
        try checkEndOfStream(buf, buf_end);
        if (buf[0] == '\r') {
            buf += 1;
            buf = try expectCharacterNoEof(buf, buf_end, '\n');
            ret_cnt += 1;
        } else if (buf[0] == '\n') {
            buf += 1;
            ret_cnt += 1;
        }
        if (ret_cnt == 2) {
            return buf;
        }
    }
}

inline fn parseInt(buf_const: [*]const u8, result: *usize, multiplier: usize) ![*]const u8 {
    var buf = buf_const;
    if (buf[0] < '0' or buf[0] > '9') {
        return error.UnexpectedCharacter;
    }
    result.* = multiplier * (buf[0] - '0');
    return buf + 1;
}

inline fn parseInt3(buf_const: [*]const u8, result: *usize) ![*]const u8 {
    var parsed: usize = 0;

    var buf = try parseInt(buf_const, &parsed, 100);
    result.* = parsed;

    buf = try parseInt(buf, &parsed, 10);
    result.* += parsed;

    buf = try parseInt(buf, &parsed, 1);
    result.* += parsed;

    return buf;
}

fn parseToken(buf_const: [*]const u8, buf_end: [*]const u8, token: *[]const u8, next_char: u8) ![*]const u8 {
    const buf_start = buf_const;

    const ranges: [*]const u8 =
        "\x00 " ++ // control chars and up to SP
        "\"\"" ++ //  0x22
        "()" ++ // 0x28,0x29
        ",," ++ // 0x2c
        "//" ++ // 0x2f
        ":@" ++ // 0x3a-0x40
        "[]" ++ // 0x5b-0x5d
        "{\xff";

    var found: bool = undefined;
    var buf = findCharacter(buf_const, buf_end, ranges, 16, &found);
    if (!found) {
        try checkEndOfStream(buf, buf_end);
    }
    while (true) {
        if (buf[0] == next_char) {
            break;
        } else if (token_char_map[buf[0]] == 0) {
            return error.UnexpectedCharacter;
        }
        buf += 1;
        try checkEndOfStream(buf, buf_end);
    }
    token.ptr = buf_start;
    token.len = @ptrToInt(buf) - @ptrToInt(buf_start);
    return buf;
}

fn parseHttpVersion(buf_const: [*]const u8, buf_end: [*]const u8, minor_version: *usize) ![*]const u8 {
    var buf = buf_const;

    // We want at least [HTTP/1.<two chars>] to try to parse.
    if (@ptrToInt(buf_end) - @ptrToInt(buf) < 9) {
        return error.EndOfStream;
    }

    inline for ("HTTP/1.") |character| {
        buf = try expectCharacter(buf, character);
    }

    buf = try parseInt(buf, minor_version, 1);

    return buf;
}

test "findCharacter" {
    const ranges: [*]const u8 =
        "\x00 " ++ // control chars and up to SP
        "\"\"" ++ //  0x22
        "()" ++ // 0x28,0x29
        ",," ++ // 0x2c
        "//" ++ // 0x2f
        ":@" ++ // 0x3a-0x40
        "[]" ++ // 0x5b-0x5d
        "{\xff";

    const input: []const u8 = "helloworlddd test";

    var found: bool = false;
    try testing.expectEqual(@as(u8, ' '), findCharacter(input.ptr, input.ptr + input.len, ranges, 16, &found)[0]);
    try testing.expect(found);
}

test "parseHttpVersion" {
    const input: []const u8 = "HTTP/1.1 ";

    var minor_version: usize = undefined;
    _ = try parseHttpVersion(input.ptr, input.ptr + input.len, &minor_version);

    try testing.expectEqual(@as(usize, 1), minor_version);
}

test "Header: read headers" {
    const input: []const u8 = "Host: localhost.com\r\nContent-Type: application/json\r\n\r\n";

    var headers: [16]Header = undefined;
    var num_headers: usize = 0;

    const len = try readHeaders(input, &headers, &num_headers, 0);
    try testing.expectEqual(input.len, len);

    try testing.expectEqual(@as(usize, 2), num_headers);

    try testing.expectEqualStrings("Host", headers[0].name);
    try testing.expectEqualStrings("localhost.com", headers[0].value);

    try testing.expectEqualStrings("Content-Type", headers[1].name);
    try testing.expectEqualStrings("application/json", headers[1].value);
}

test "Request: read request" {
    const input: []const u8 = "GET   /hello     HTTP/1.1\r\nContent-Length: 123\r\n Paragraph\r\nHello-World: test \r\n\r\n";

    var headers: [16]Header = undefined;
    var request: Request = .{ .headers = &headers };

    const len = try readRequest(input, &request, 0);
    try testing.expectEqual(input.len, len);

    try testing.expectEqualStrings("GET", request.method);
    try testing.expectEqualStrings("/hello", request.path);
    try testing.expectEqual(@as(usize, 1), request.minor_version);

    try testing.expectEqual(@as(usize, 3), request.num_headers);

    try testing.expectEqualStrings("Content-Length", request.headers[0].name);
    try testing.expectEqualStrings("123", request.headers[0].value);

    try testing.expectEqualStrings("", request.headers[1].name);
    try testing.expectEqualStrings(" Paragraph", request.headers[1].value);

    try testing.expectEqualStrings("Hello-World", request.headers[2].name);
    try testing.expectEqualStrings("test", request.headers[2].value);
}

test "Response: read response" {
    const input: []const u8 = "HTTP/1.1    200    Some Status Text\r\nContent-Length: 123  \r\n Paragraph\r\nHello-World: test \r\n\r\n";

    var headers: [16]Header = undefined;
    var response: Response = .{ .headers = &headers };

    const len = try readResponse(input, &response, 0);
    try testing.expectEqual(input.len, len);

    try testing.expectEqual(@as(usize, 1), response.minor_version);
    try testing.expectEqual(@as(usize, 200), response.status_code);
    try testing.expectEqualStrings("Some Status Text", response.message);

    try testing.expectEqual(@as(usize, 3), response.num_headers);

    try testing.expectEqualStrings("Content-Length", response.headers[0].name);
    try testing.expectEqualStrings("123", response.headers[0].value);

    try testing.expectEqualStrings("", response.headers[1].name);
    try testing.expectEqualStrings(" Paragraph", response.headers[1].value);

    try testing.expectEqualStrings("Hello-World", response.headers[2].name);
    try testing.expectEqualStrings("test", response.headers[2].value);
}

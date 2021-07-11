const std = @import("std");
const binary = @import("binary.zig");

const math = std.math;
const meta = std.meta;
const testing = std.testing;

const assert = std.debug.assert;

const Packet = @This();

pub const header_size = binary.sizeOf(Packet.Header);

pub const Type = enum(u8) {
    command,
    request,
    response,

    pub fn validate(self: Packet.Type) !void {
        assert(self == try meta.intToEnum(Packet.Type, @enumToInt(self)));
    }
};

pub const Tag = enum(u8) {
    ping,
    push_transaction,
    pull_transaction,
    pull_block,

    pub fn validate(self: Packet.Tag) !void {
        assert(self == try meta.intToEnum(Packet.Tag, @enumToInt(self)));
    }
};

pub const Header = struct {
    nonce: u32,
    @"type": Packet.Type,
    tag: Packet.Tag,
};

buffer: []const u8,

pub usingnamespace binary.Decoder(Packet, Packet.Header);

pub fn unmarshal(buffer: []const u8) !Packet {
    var packet: Packet = .{ .buffer = buffer };
    packet.buffer = packet.buffer[0..try packet.validate()];
    return packet;
}

pub fn validate(self: Packet) !usize {
    if (self.buffer.len < Packet.header_size) {
        return error.ShortBuffer;
    }
    try self.get(.type).validate();
    try self.get(.tag).validate();
    return Packet.header_size;
}

pub fn append(dst: binary.Buffer, data: Packet.Header) !binary.Buffer {
    return binary.write(dst, data);
}

test "packet: append and unmarshal" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    const data = try Packet.append(binary.Buffer.from(&buf), .{
        .nonce = 123,
        .@"type" = .command,
        .tag = .ping,
    });

    const packet = try Packet.unmarshal(data.items());
    try testing.expectEqual(@as(u32, 123), packet.get(.nonce));
    try testing.expectEqual(Packet.Type.command, packet.get(.type));
    try testing.expectEqual(Packet.Tag.ping, packet.get(.tag));
}

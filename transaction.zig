const std = @import("std");

const math = std.math;
const testing = std.testing;

const Ed25519 = std.crypto.sign.Ed25519;

usingnamespace @import("binary.zig");

pub const Transaction = struct {
    pub const Tag = enum(u8) {
        no_op,
    };

    pub const Data = struct {
        sender_nonce: u64,
        created_at: u64,
        tag: Transaction.Tag,
        data: []const u8,
    };

    id: [32]u8,
    buffer: []const u8,

    pub fn signAndAppend(dst: Buffer, keys: Ed25519.KeyPair, data: Transaction.Data) !Buffer {
        const header_size = sizeOfAll(.{ .sender = [32]u8, .signature = [64]u8, .data_len = u32 });
        const body = try writeAll((try dst.allocate(header_size)).sliceFromEnd(), data);

        const header = try writeAll(dst, .{
            .sender = keys.public_key,
            .signature = try Ed25519.sign(body.items(), keys, null),
            .data_len = try math.cast(u32, data.data.len),
        });

        return header.slice(0, header.len + body.len);
    }
};

test "transaction: sign and append" {
    const keys = try Ed25519.KeyPair.create(null);

    var dst = std.ArrayList(u8).init(testing.allocator);
    defer dst.deinit();

    const slice = try Transaction.signAndAppend(Buffer.from(&dst), keys, .{
        .sender_nonce = 123,
        .created_at = 456,
        .tag = .no_op,
        .data = "abcedfghijklmnopqrstuvwxyz",
    });

    _ = slice;
}

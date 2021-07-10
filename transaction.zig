const std = @import("std");
const binary = @import("binary.zig");

const mem = std.mem;
const math = std.math;
const meta = std.meta;
const testing = std.testing;

const Ed25519 = std.crypto.sign.Ed25519;
const Blake3 = std.crypto.hash.Blake3;

const assert = std.debug.assert;

pub const Transaction = struct {
    pub const header_size = binary.sizeOfAll(Transaction.Header);
    pub const data_size = binary.sizeOfAll(Transaction.Data);

    pub const Tag = enum(u8) {
        no_op,

        pub fn validate(self: Transaction.Tag) !void {
            assert(self == try meta.intToEnum(Transaction.Tag, @enumToInt(self)));
        }
    };

    pub const Header = struct {
        sender: [32]u8,
        signature: [64]u8,
        data_len: u32,
    };

    pub const Data = struct {
        sender_nonce: u64,
        created_at: u64,
        tag: Transaction.Tag,
        data: []const u8,
    };

    id: [32]u8 = undefined,
    buffer: []const u8,

    pub usingnamespace binary.Decoder(Transaction, .{ Transaction.Header, Transaction.Data });

    pub fn unmarshal(buffer: []const u8) !Transaction {
        var tx: Transaction = .{ .buffer = buffer };
        tx.buffer = tx.buffer[0..try tx.validate()];
        Blake3.hash(tx.buffer, &tx.id, .{});
        return tx;
    }

    pub fn unmarshalBatch(dst: *std.ArrayList(Transaction), buffer: []const u8) !usize {
        var bytes_read: usize = 0;
        while (bytes_read < buffer.len) {
            const tx = Transaction.unmarshal(buffer[bytes_read..]) catch |err| return switch (err) {
                error.ShortBuffer => bytes_read,
                else => err,
            };
            try dst.append(tx);
            bytes_read += tx.buffer.len;
        }
        return bytes_read;
    }

    pub fn validate(self: Transaction) !usize {
        if (self.buffer.len < Transaction.header_size + Transaction.data_size) {
            return error.ShortBuffer;
        }
        const data_len = self.get(.data_len);
        if (self.buffer[Transaction.header_size + Transaction.data_size ..].len < data_len) {
            return error.ShortBuffer;
        }
        try self.get(.tag).validate();
        return Transaction.header_size + Transaction.data_size + data_len;
    }

    pub fn signAndAppend(dst: binary.Buffer, keys: Ed25519.KeyPair, data: Transaction.Data) !binary.Buffer {
        const body = try binary.writeAll((try binary.allocateAll(dst, Transaction.Header)).sliceFromEnd(), data);

        const header = try binary.writeAll(dst, Transaction.Header{
            .sender = keys.public_key,
            .signature = try Ed25519.sign(body.items(), keys, null),
            .data_len = try math.cast(u32, data.data.len),
        });

        return header.slice(0, header.len + body.len);
    }
};

test "transaction: sign, append, unmarshal, and hash" {
    const keys = try Ed25519.KeyPair.create(null);

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    const data = try Transaction.signAndAppend(binary.Buffer.from(&buf), keys, .{
        .sender_nonce = 123,
        .created_at = 456,
        .tag = .no_op,
        .data = "abcdefghijklmnopqrstuvwxyz",
    });

    const tx = try Transaction.unmarshal(data.items());
    try testing.expectEqual(@as(u64, 123), tx.get(.sender_nonce));
    try testing.expectEqual(@as(u64, 456), tx.get(.created_at));
    try testing.expectEqual(Transaction.Tag.no_op, tx.get(.tag));
    try testing.expectEqualSlices(u8, "abcdefghijklmnopqrstuvwxyz", tx.get(.data)[0..tx.get(.data_len)]);

    var hash: [32]u8 = undefined;
    Blake3.hash(data.items(), &hash, .{});

    try testing.expectEqualSlices(u8, &hash, &tx.id);
}

test "transaction: sign, append, and unmarshal batch" {
    const keys = try Ed25519.KeyPair.create(null);
    const count = 10;

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    {
        var i: u64 = 0;
        while (i < count) : (i += 1) {
            _ = try Transaction.signAndAppend(binary.Buffer.from(&buf), keys, .{
                .sender_nonce = i,
                .created_at = i,
                .tag = .no_op,
                .data = "abcdefghijklmnopqrstuvwxyz",
            });
        }
    }

    var transactions = std.ArrayList(Transaction).init(testing.allocator);
    defer transactions.deinit();

    try testing.expectEqual(buf.items.len, try Transaction.unmarshalBatch(&transactions, buf.items));
    try testing.expectEqual(transactions.items.len, count);

    {
        var i: u64 = 0;
        while (i < count) : (i += 1) {
            const tx = transactions.items[@intCast(usize, i)];
            try testing.expectEqual(i, tx.get(.sender_nonce));
            try testing.expectEqual(i, tx.get(.created_at));
            try testing.expectEqual(Transaction.Tag.no_op, tx.get(.tag));
            try testing.expectEqualSlices(u8, "abcdefghijklmnopqrstuvwxyz", tx.get(.data)[0..tx.get(.data_len)]);
        }
    }
}

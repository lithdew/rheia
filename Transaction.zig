const std = @import("std");
const binary = @import("binary.zig");

const mem = std.mem;
const math = std.math;
const meta = std.meta;
const testing = std.testing;

const Ed25519 = std.crypto.sign.Ed25519;
const Blake3 = std.crypto.hash.Blake3;

const assert = std.debug.assert;

const Transaction = @This();

pub const header_size = binary.sizeOf(Transaction.Header);

pub const Tag = enum(u8) {
    no_op,

    pub fn validate(self: Transaction.Tag) !void {
        assert(self == try meta.intToEnum(Transaction.Tag, @enumToInt(self)));
    }
};

pub const Header = struct {
    sender: [32]u8,
    signature: [64]u8,
    body_len: u32,
    sender_nonce: u64,
    created_at: u64,
    tag: Transaction.Tag,
};

pub const Fields = struct {
    sender_nonce: u64,
    created_at: u64,
    tag: Transaction.Tag,
    body: []const u8,
};

pub const Iterator = struct {
    buffer: []const u8,
    bytes_read: usize = 0,

    pub fn next(self: *Transaction.Iterator) !?Transaction {
        if (self.bytes_read == self.buffer.len) return null;
        const tx = Transaction.unmarshal(self.buffer[self.bytes_read..]) catch |err| return switch (err) {
            error.ShortBuffer => null,
            else => err,
        };
        self.bytes_read += tx.buffer.len;
        return tx;
    }

    pub fn reset(self: *Transaction.Iterator) void {
        self.bytes_read = 0;
    }
};

id: [32]u8 = undefined,
buffer: []const u8,

pub usingnamespace binary.Decoder(Transaction, Transaction.Header);

pub fn iterator(buffer: []const u8) Transaction.Iterator {
    return .{ .buffer = buffer };
}

pub fn unmarshalBatch(dst: *std.ArrayList(Transaction), buffer: []const u8) !usize {
    var it = Transaction.iterator(buffer);
    while (try it.next()) |tx| {
        try dst.append(tx);
    }
    return it.bytes_read;
}

pub fn unmarshal(buffer: []const u8) !Transaction {
    var tx: Transaction = .{ .buffer = buffer };
    tx.buffer = tx.buffer[0..try tx.validate()];
    Blake3.hash(tx.buffer, &tx.id, .{});
    return tx;
}

pub fn validate(self: Transaction) !usize {
    if (self.buffer.len < Transaction.header_size) {
        return error.ShortBuffer;
    }
    const body_len = self.get(.body_len);
    if (self.buffer[Transaction.header_size..].len < body_len) {
        return error.ShortBuffer;
    }
    try self.get(.tag).validate();
    return Transaction.header_size + body_len;
}

pub fn signAndAppend(dst: binary.Buffer, keys: Ed25519.KeyPair, fields: Transaction.Fields) !binary.Buffer {
    const Metadata = binary.StructSlice(Transaction.Header, .sender, .body_len);
    const metadata_bytes = try binary.allocate(dst, Metadata);

    const body = try binary.write(metadata_bytes.sliceFromEnd(), fields);

    const metadata = binary.writeAssumeCapacity(dst, Metadata{
        .sender = keys.public_key,
        .signature = try Ed25519.sign(body.items(), keys, null),
        .body_len = try math.cast(u32, fields.body.len),
    });

    return metadata.slice(0, metadata.len + body.len);
}

pub fn getBody(self: Transaction) []const u8 {
    return (self.buffer.ptr + Transaction.header_size)[0..self.get(.body_len)];
}

test "transaction: sign, append, unmarshal, and hash" {
    const keys = try Ed25519.KeyPair.create(null);

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    const data = try Transaction.signAndAppend(binary.Buffer.from(&buf), keys, .{
        .sender_nonce = 123,
        .created_at = 456,
        .tag = .no_op,
        .body = "abcdefghijklmnopqrstuvwxyz",
    });

    const tx = try Transaction.unmarshal(data.items());
    try testing.expectEqual(@as(u64, 123), tx.get(.sender_nonce));
    try testing.expectEqual(@as(u64, 456), tx.get(.created_at));
    try testing.expectEqual(Transaction.Tag.no_op, tx.get(.tag));
    try testing.expectEqualSlices(u8, "abcdefghijklmnopqrstuvwxyz", tx.getBody());

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
                .body = "abcdefghijklmnopqrstuvwxyz",
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
            try testing.expectEqualSlices(u8, "abcdefghijklmnopqrstuvwxyz", tx.getBody());
        }
    }
}

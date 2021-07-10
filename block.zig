const std = @import("std");
const binary = @import("binary.zig");

const mem = std.mem;
const math = std.math;
const meta = std.meta;
const testing = std.testing;

const Blake3 = std.crypto.hash.Blake3;

pub const Block = struct {
    pub const header_size = binary.sizeOfAll(Block.Header);

    pub const Header = struct {
        height: u64,
        merkle_root: [32]u8,
        transaction_ids_len: u32,
        transaction_ids: []const [32]u8,
    };

    pub const Data = struct {
        height: u64,
        merkle_root: [32]u8,
        transaction_ids: []const [32]u8,
    };

    id: [32]u8 = undefined,
    buffer: []const u8,

    pub usingnamespace binary.Decoder(Block, Block.Header);

    pub fn unmarshal(buffer: []const u8) !Block {
        var block: Block = .{ .buffer = buffer };
        block.buffer = block.buffer[0..try block.validate()];
        Blake3.hash(block.buffer, &block.id, .{});
        return block;
    }

    pub fn validate(self: Block) !usize {
        if (self.buffer.len < header_size) {
            return error.ShortBuffer;
        }
        const transaction_ids_len = self.get(.transaction_ids_len);
        if (self.buffer[Block.header_size..].len < transaction_ids_len * binary.sizeOf([32]u8)) {
            return error.ShortBuffer;
        }
        return Block.header_size + transaction_ids_len * binary.sizeOf([32]u8);
    }

    pub fn append(dst: binary.Buffer, data: Block.Data) !binary.Buffer {
        const header = try binary.writeAll(dst, .{
            .height = data.height,
            .merkle_root = data.merkle_root,
            .transaction_ids_len = @intCast(u32, data.transaction_ids.len),
        });

        const body = try header.sliceFromEnd().allocate(data.transaction_ids.len * binary.sizeOf([32]u8));
        mem.copy([32]u8, @ptrCast([*][32]u8, body.ptr())[0..data.transaction_ids.len], data.transaction_ids);

        return dst.slice(0, Block.header_size + body.len);
    }
};

test "block: append, unmarshal, and hash" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    const data = try Block.append(binary.Buffer.from(&buf), .{
        .height = 123,
        .merkle_root = [_]u8{1} ** 32,
        .transaction_ids = &([_][32]u8{[_]u8{2} ** 32} ** 16),
    });

    const block = try Block.unmarshal(data.items());
    try testing.expectEqual(@as(u64, 123), block.get(.height));
    try testing.expectEqual([_]u8{1} ** 32, block.get(.merkle_root));
    try testing.expectEqualSlices([32]u8, &([_][32]u8{[_]u8{2} ** 32} ** 16), block.get(.transaction_ids)[0..block.get(.transaction_ids_len)]);

    var hash: [32]u8 = undefined;
    Blake3.hash(data.items(), &hash, .{});

    try testing.expectEqualSlices(u8, &hash, &block.id);
}

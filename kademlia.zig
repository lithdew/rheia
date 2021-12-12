const std = @import("std");
const net = @import("net.zig");
const sync = @import("sync.zig");
const rheia = @import("main.zig");
const runtime = @import("runtime.zig");

const io = std.io;
const ip = std.x.net.ip;
const fmt = std.fmt;
const mem = std.mem;
const meta = std.meta;
const testing = std.testing;

const IPv4 = std.x.os.IPv4;
const IPv6 = std.x.os.IPv6;
const Context = runtime.Context;
const SortedHashMap = @import("hash_map.zig").SortedHashMap;
const AutoStaticHashMap = @import("hash_map.zig").AutoStaticHashMap;
const StaticRingBuffer = @import("ring_buffer.zig").StaticRingBuffer;

const assert = std.debug.assert;

const kademlia = @This();

pub const ID = struct {
    pub const header_size = @sizeOf([32]u8);

    public_key: [32]u8,
    address: ip.Address,

    pub fn eql(self: ID, other: ID) bool {
        return net.eqlIpAddress(self.address, other.address) and
            mem.eql(u8, &self.public_key, &other.public_key);
    }

    pub fn size(self: ID) u32 {
        return ID.header_size + @sizeOf(u8) + @as(u32, switch (self.address) {
            .ipv4 => @sizeOf([4]u8),
            .ipv6 => @sizeOf([16]u8) + @sizeOf(u32),
        }) + @sizeOf(u16);
    }

    pub fn write(self: ID, writer: anytype) !void {
        try writer.writeAll(&self.public_key);
        try writer.writeByte(@enumToInt(self.address));
        switch (self.address) {
            .ipv4 => |info| {
                try writer.writeAll(&info.host.octets);
                try writer.writeIntLittle(u16, info.port);
            },
            .ipv6 => |info| {
                try writer.writeAll(&info.host.octets);
                try writer.writeIntLittle(u32, info.host.scope_id);
                try writer.writeIntLittle(u16, info.port);
            },
        }
    }

    pub fn writeSignaturePayload(self: ID, writer: anytype) !void {
        try self.write(writer);
    }

    pub fn read(reader: anytype) !ID {
        var id: ID = undefined;
        id.public_key = try reader.readBytesNoEof(32);

        switch (try meta.intToEnum(meta.Tag(ip.Address), try reader.readByte())) {
            .ipv4 => {
                const host = IPv4{ .octets = try reader.readBytesNoEof(4) };
                const port = try reader.readIntLittle(u16);
                id.address = ip.Address.initIPv4(host, port);
            },
            .ipv6 => {
                const host = IPv6{
                    .octets = try reader.readBytesNoEof(16),
                    .scope_id = try reader.readIntLittle(u32),
                };
                const port = try reader.readIntLittle(u16);
                id.address = ip.Address.initIPv6(host, port);
            },
        }

        return id;
    }

    pub fn format(self: ID, comptime layout: []const u8, options: fmt.FormatOptions, writer: anytype) !void {
        _ = layout;
        _ = options;
        try fmt.format(writer, "{}[{}]", .{ self.address, fmt.fmtSliceHexLower(&self.public_key) });
    }
};

pub const NodeFinder = struct {
    const log = std.log.scoped(.node_finder);

    node: *rheia.Node,
    visited: SortedHashMap(void, 50),
    pool: sync.BoundedTaskPool(visit) = .{ .capacity = 16 },

    pub fn init(gpa: mem.Allocator, node: *rheia.Node) !NodeFinder {
        return NodeFinder{ .node = node, .visited = try SortedHashMap(void, 50).initCapacity(gpa, 16) };
    }

    pub fn deinit(self: *NodeFinder, ctx: *Context, gpa: mem.Allocator) void {
        self.pool.deinit(ctx, gpa) catch |err| log.warn("error while shutting down: {}", .{err});
        self.visited.deinit(gpa);
    }

    pub fn find(
        self: *NodeFinder,
        ctx: *Context,
        gpa: mem.Allocator,
        dst: []ID,
        public_key: [32]u8,
    ) !usize {
        var wg: sync.WaitGroup = .{};
        errdefer wg.wait(ctx) catch {};

        var count = self.node.table.closestTo(dst, public_key);
        defer self.visited.clearRetainingCapacity();

        try self.visited.ensureUnusedCapacity(gpa, count);

        for (dst[0..count]) |id| {
            try self.pool.spawn(ctx, gpa, .{ self, ctx, gpa, &wg, dst, &count, id, public_key });
            self.visited.putAssumeCapacity(id.public_key, {});
        }

        try wg.wait(ctx);

        return count;
    }

    pub fn visit(
        self: *NodeFinder,
        ctx: *Context,
        gpa: mem.Allocator,
        wg: *sync.WaitGroup,
        dst: []ID,
        count: *usize,
        id: ID,
        public_key: [32]u8,
    ) !void {
        wg.add(1);
        defer wg.sub(1);

        const client = try self.node.getOrCreateClient(ctx, gpa, id.address);

        var entry: net.RPC.Entry = .{};
        var nonce = try client.rpc.register(ctx, &entry);

        {
            const writer = try client.acquireWriter(ctx, gpa);
            defer client.releaseWriter(writer);

            try (net.Packet{
                .len = @sizeOf([32]u8),
                .nonce = nonce,
                .op = .request,
                .tag = .find_node,
            }).write(writer);

            try writer.writeAll(&public_key);
        }

        const response = try await entry.response;
        defer response.deinit(gpa);

        var body = io.fixedBufferStream(response.body);

        while (true) {
            const peer_id = ID.read(body.reader()) catch break;

            const visited = self.visited.getOrPut(gpa, peer_id.public_key) catch continue;
            if (visited.found_existing) continue;
            visited.value_ptr.* = {};

            const result = RoutingTable.binarySearch(public_key, dst[0..count.*], peer_id.public_key);
            assert(result != .found);

            const index = result.not_found;
            if (count.* < dst.len) {
                count.* += 1;
            } else if (index >= count.*) {
                continue;
            }
            var j: usize = count.* - 1;
            while (j > index) : (j -= 1) {
                dst[j] = dst[j - 1];
            }
            dst[index] = peer_id;

            self.pool.spawn(ctx, gpa, .{ self, ctx, gpa, wg, dst, count, peer_id, public_key }) catch continue;
        }
    }
};

pub const RoutingTable = struct {
    pub const bucket_size = 16;

    pub const Bucket = StaticRingBuffer(ID, u64, bucket_size);

    public_key: [32]u8,
    buckets: [256]Bucket = [_]Bucket{.{}} ** 256,
    addresses: AutoStaticHashMap(ip.Address, ID, 256 * bucket_size) = .{},
    len: usize = 0,

    fn clz(public_key: [32]u8) usize {
        comptime var i = 0;
        inline while (i < 32) : (i += 1) {
            if (public_key[i] != 0) {
                return i * 8 + @as(usize, @clz(u8, public_key[i]));
            }
        }
        return 256;
    }

    fn xor(a: [32]u8, b: [32]u8) [32]u8 {
        return @as([32]u8, @as(meta.Vector(32, u8), a) ^ @as(meta.Vector(32, u8), b));
    }

    pub const PutResult = enum {
        full,
        updated,
        inserted,
    };

    fn removeFromBucket(bucket: *Bucket, public_key: [32]u8) bool {
        var i: usize = bucket.head;
        var j: usize = bucket.head;
        while (i != bucket.tail) : (i -%= 1) {
            const it = bucket.entries[(i -% 1) & (bucket_size - 1)];
            if (!mem.eql(u8, &it.public_key, &public_key)) {
                bucket.entries[(j -% 1) & (bucket_size - 1)] = it;
                j -%= 1;
            }
        }
        if (i != j) {
            bucket.entries[(j -% 1) & (bucket_size - 1)] = undefined;
            bucket.tail = j;
        }
        return i != j;
    }

    pub fn put(self: *RoutingTable, id: ID) PutResult {
        if (mem.eql(u8, &self.public_key, &id.public_key)) {
            return .full;
        }

        const bucket = &self.buckets[clz(xor(self.public_key, id.public_key))];

        const result = self.addresses.getOrPutAssumeCapacity(id.address);
        const removed = removed: {
            if (result.found_existing) {
                const other_bucket = &self.buckets[clz(xor(self.public_key, result.value_ptr.public_key))];
                break :removed removeFromBucket(other_bucket, result.value_ptr.public_key);
            }
            break :removed removeFromBucket(bucket, id.public_key);
        };
        result.value_ptr.* = id;

        if (!removed and bucket.count() == bucket_size) {
            return .full;
        }

        bucket.push(id);

        if (removed) {
            return .updated;
        }

        self.len += 1;
        return .inserted;
    }

    pub fn delete(self: *RoutingTable, public_key: [32]u8) bool {
        if (self.len == 0 or mem.eql(u8, &self.public_key, &public_key)) {
            return false;
        }

        const bucket = &self.buckets[clz(xor(self.public_key, public_key))];
        if (!removeFromBucket(bucket, public_key)) {
            return false;
        }

        self.len -= 1;
        return true;
    }

    pub fn closestTo(self: *const RoutingTable, dst: []ID, public_key: [32]u8) usize {
        var count: usize = 0;

        const bucket_index = clz(xor(self.public_key, public_key));
        if (!mem.eql(u8, &self.public_key, &public_key)) {
            self.fillSort(dst, &count, public_key, bucket_index);
        }

        var index: usize = 1;
        while (count < dst.len) : (index += 1) {
            var stop = true;
            if (bucket_index >= index) {
                self.fillSort(dst, &count, public_key, bucket_index - index);
                stop = false;
            }
            if (bucket_index + index < self.buckets.len) {
                self.fillSort(dst, &count, public_key, bucket_index + index);
                stop = false;
            }
            if (stop) {
                break;
            }
        }

        return count;
    }

    const BinarySearchResult = union(enum) {
        found: usize,
        not_found: usize,
    };

    fn binarySearch(our_public_key: [32]u8, slice: []ID, public_key: [32]u8) BinarySearchResult {
        var size: usize = slice.len;
        var left: usize = 0;
        var right: usize = slice.len;
        while (left < right) {
            const mid = left + size / 2;
            switch (mem.order(
                u8,
                &xor(slice[mid].public_key, our_public_key),
                &xor(public_key, our_public_key),
            )) {
                .lt => left = mid + 1,
                .gt => right = mid,
                .eq => return .{ .found = mid },
            }
            size = right - left;
        }
        return .{ .not_found = left };
    }

    fn fillSort(self: *const RoutingTable, dst: []ID, count: *usize, public_key: [32]u8, bucket_index: usize) void {
        const bucket = &self.buckets[bucket_index];

        var i: usize = bucket.head;
        while (i != bucket.tail) : (i -%= 1) {
            const it = bucket.entries[(i -% 1) & (bucket_size - 1)];
            if (!mem.eql(u8, &it.public_key, &public_key)) {
                const result = binarySearch(self.public_key, dst[0..count.*], it.public_key);
                assert(result != .found);

                const index = result.not_found;
                if (count.* < dst.len) {
                    count.* += 1;
                } else if (index >= count.*) {
                    continue;
                }
                var j: usize = count.* - 1;
                while (j > index) : (j -= 1) {
                    dst[j] = dst[j - 1];
                }
                dst[index] = it;
            }
        }
    }
};

test "ID: serialize and deserialize" {
    var seed: usize = 0;
    while (seed < 128) : (seed += 1) {
        var rng = std.rand.DefaultPrng.init(seed);

        var public_key: [32]u8 = undefined;
        rng.random().bytes(&public_key);

        const address = address: {
            switch (rng.random().boolean()) {
                true => {
                    var host_octets: [4]u8 = undefined;
                    rng.random().bytes(&host_octets);

                    const host = IPv4{ .octets = host_octets };
                    const port = rng.random().int(u16);
                    break :address ip.Address.initIPv4(host, port);
                },
                false => {
                    var host_octets: [16]u8 = undefined;
                    rng.random().bytes(&host_octets);

                    const host = IPv6{ .octets = host_octets, .scope_id = rng.random().int(u32) };
                    const port = rng.random().int(u16);
                    break :address ip.Address.initIPv6(host, port);
                },
            }
        };

        const expected: ID = .{ .public_key = public_key, .address = address };

        var data = std.ArrayList(u8).init(testing.allocator);
        defer data.deinit();

        try expected.write(data.writer());

        const actual = try ID.read(io.fixedBufferStream(data.items).reader());

        try testing.expectEqual(expected, actual);
    }
}

test "RoutingTable" {
    const public_key: [32]u8 = [_]u8{0xFF} ** 32;

    var table: RoutingTable = .{ .public_key = public_key };

    // put (free)

    comptime var i: u8 = 1;
    inline while (i <= 16) : (i += 1) {
        try testing.expectEqual(RoutingTable.PutResult.inserted, table.put(ID{
            .public_key = [_]u8{ 0, i } ++ [_]u8{0} ** 30,
            .address = ip.Address.initIPv4(IPv4.unspecified, @as(u16, 9000) + i),
        }));
    }

    try testing.expectEqual([_]u8{ 0, 01 } ++ [_]u8{0} ** 30, table.buckets[0].oldest().?.public_key);
    try testing.expectEqual([_]u8{ 0, 16 } ++ [_]u8{0} ** 30, table.buckets[0].latest().?.public_key);
    try testing.expectEqual(@as(usize, 16), table.len);

    // put (full)

    try testing.expectEqual(RoutingTable.PutResult.full, table.put(ID{
        .public_key = [_]u8{ 0, 17 } ++ [_]u8{0} ** 30,
        .address = ip.Address.initIPv4(IPv4.unspecified, 9017),
    }));
    try testing.expectEqual(@as(usize, 16), table.len);

    // put (update)

    try testing.expectEqual(RoutingTable.PutResult.updated, table.put(ID{
        .public_key = [_]u8{ 0, 01 } ++ [_]u8{0} ** 30,
        .address = ip.Address.initIPv4(IPv4.unspecified, 9001),
    }));
    try testing.expectEqual([_]u8{ 0, 02 } ++ [_]u8{0} ** 30, table.buckets[0].oldest().?.public_key);
    try testing.expectEqual([_]u8{ 0, 01 } ++ [_]u8{0} ** 30, table.buckets[0].latest().?.public_key);
    try testing.expectEqual(@as(usize, 16), table.len);

    // closest to

    var ids: [15]ID = undefined;
    try testing.expectEqual(@as(usize, 15), table.closestTo(&ids, [_]u8{ 0, 1 } ++ [_]u8{0} ** 30));

    comptime var j: u8 = 0;
    inline while (j < 15) : (j += 1) {
        try testing.expectEqual(16 - j, ids[j].public_key[1]);
    }

    // delete

    comptime var k: u8 = 1;
    inline while (k <= 16) : (k += 1) {
        try testing.expect(table.delete([_]u8{ 0, k } ++ [_]u8{0} ** 30));
    }

    try testing.expectEqual(@as(?ID, null), table.buckets[0].latest());
    try testing.expectEqual(@as(?ID, null), table.buckets[0].oldest());
    try testing.expectEqual(@as(usize, 0), table.len);
}

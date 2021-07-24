const std = @import("std");
const binary = @import("../binary.zig");
const Packet = @import("../Packet.zig");

pub const log_level = .debug;

pub fn main() !void {
    const gpa = std.heap.c_allocator;

    var timer = try std.time.Timer.start();
    var count: usize = 0;
    while (true) : (count += 1) {
        if (timer.read() > 1 * std.time.ns_per_s) {
            timer.reset();

            std.log.info("serialized {} messages in the last second", .{count});
            count = 0;
        }

        var buf = std.ArrayList(u8).init(gpa);
        defer buf.deinit();

        const Node = std.SinglyLinkedList([]const u8).Node;
        const node_data = try binary.Buffer.from(&buf).allocate(@sizeOf(Node));

        var size_data = try binary.allocate(node_data.sliceFromEnd(), u32);
        var body_data = try Packet.append(size_data.sliceFromEnd(), .{ .nonce = 0, .@"type" = .request, .tag = .ping });
        size_data = binary.writeAssumeCapacity(node_data.sliceFromEnd(), @intCast(u32, size_data.len + body_data.len));

        const node = @ptrCast(*Node, @alignCast(@alignOf(*Node), node_data.ptr()));
        node.* = .{ .data = size_data.ptr()[0 .. size_data.len + body_data.len] };
    }
}

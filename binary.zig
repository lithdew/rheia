const std = @import("std");

const mem = std.mem;
const meta = std.meta;
const testing = std.testing;

const assert = std.debug.assert;

pub const Buffer = struct {
    parent: *std.ArrayList(u8),
    offset: usize,
    len: usize,

    /// Wraps an array list into a buffer.
    pub fn from(parent: *std.ArrayList(u8)) Buffer {
        return Buffer{ .parent = parent, .offset = 0, .len = parent.items.len };
    }

    /// Returns a buffer that is a subslice of this buffer.
    pub fn slice(self: Buffer, start: usize, end: usize) Buffer {
        assert(self.offset + start <= self.parent.capacity and self.offset + end <= self.parent.capacity);
        return Buffer{ .parent = self.parent, .offset = self.offset + start, .len = end - start };
    }

    /// Returns a buffer sliced starting from the beginning of this buffer.
    pub fn sliceFromStart(self: Buffer) Buffer {
        return Buffer{ .parent = self.parent, .offset = self.offset, .len = 0 };
    }

    /// Returns a buffer sliced starting from the end of this buffer.
    pub fn sliceFromEnd(self: Buffer) Buffer {
        return Buffer{ .parent = self.parent, .offset = self.offset + self.len, .len = 0 };
    }

    /// Returns the underlying slice this buffer wraps around.
    pub fn items(self: Buffer) []u8 {
        return (self.parent.items.ptr + self.offset)[0..self.len];
    }

    /// Allocates len bytes to the end of the buffer.
    pub fn allocate(self: Buffer, len: usize) !Buffer {
        try self.parent.ensureTotalCapacity(self.offset + self.len + len);
        return Buffer{ .parent = self.parent, .offset = self.offset, .len = self.len + len };
    }

    /// Appends buf to the end of the buffer.
    pub fn append(self: Buffer, buf: []const u8) !Buffer {
        try self.parent.ensureTotalCapacity(self.offset + self.len + buf.len);
        mem.copy(u8, (self.parent.items.ptr + self.offset + self.len)[0..buf.len], buf);
        return Buffer{ .parent = self.parent, .offset = self.offset, .len = self.len + buf.len };
    }

    /// Appends multiple bufs to the end of the buffer. Buffers that are passed in may safely
    /// alias with one another. Only performs at most a single std.mem.Allocator.resize operation
    /// when appending multiple buffers in comparison to Buffer.append.
    pub fn appendAll(self: Buffer, bufs: []const []const u8) !Buffer {
        const size = size: {
            var size: usize = 0;
            for (bufs) |buf| size += buf.len;
            break :size size;
        };

        try self.parent.ensureTotalCapacity(self.offset + self.len + size);

        var len = self.len;
        for (bufs) |buf| {
            mem.copy(u8, (self.parent.items.ptr + self.offset + len)[0..buf.len], buf);
            len += buf.len;
        }
        return Buffer{ .parent = self.parent, .offset = self.offset, .len = len };
    }
};

pub fn sizeOf(T: anytype) usize {
    if (comptime @TypeOf(T) != type) {
        if (comptime meta.trait.isZigString(@TypeOf(T))) {
            return T.len;
        }
        return sizeOf(@TypeOf(T));
    }

    if (comptime @typeInfo(T) == .Enum) {
        return @sizeOf(@typeInfo(T).Enum.child);
    } else if (comptime @typeInfo(T) == .Int) {
        return @sizeOf(T);
    } else if (comptime @typeInfo(T) == .Array and @typeInfo(T).Array.child == u8) {
        return @sizeOf(T);
    } else {
        @compileError("Unsupported type '" ++ @typeName(T) ++ "'");
    }
}

pub fn sizeOfAll(T: anytype) usize {
    var size: usize = 0;

    if (comptime @TypeOf(T) == type and @typeInfo(T) == .Struct) {
        inline for (@typeInfo(T).Struct.fields) |field| {
            size += sizeOf(field.field_type);
        }
    } else if (comptime @typeInfo(@TypeOf(T)) == .Struct) {
        inline for (@typeInfo(@TypeOf(T)).Struct.fields) |field| {
            size += sizeOf(@field(T, field.name));
        }
    } else {
        @compileError("Unsupported type '" ++ @typeName(T) ++ "'");
    }

    return size;
}

pub fn sliceOf(val: anytype) []const u8 {
    const T = @TypeOf(val);
    if (comptime meta.trait.is(.Enum)(T)) {
        return mem.asBytes(&mem.nativeToLittle(@TypeOf(@enumToInt(val)), @enumToInt(val)));
    } else if (comptime @typeInfo(T) == .Int) {
        return mem.asBytes(&mem.nativeToLittle(T, val));
    } else if (comptime @typeInfo(T) == .Array and @typeInfo(T).Array.child == u8) {
        return &val;
    } else if (comptime meta.trait.isZigString(T)) {
        return val;
    } else {
        @compileError("Unsupported type '" ++ @typeName(T) ++ "'");
    }
}

pub fn write(dst: Buffer, val: anytype) !Buffer {
    return dst.append(sliceOf(val));
}

pub fn writeAll(dst: Buffer, vals: anytype) !Buffer {
    comptime assert(meta.trait.is(.Struct)(@TypeOf(vals)));

    var bufs: [@typeInfo(@TypeOf(vals)).Struct.fields.len][]const u8 = undefined;
    inline for (@typeInfo(@TypeOf(vals)).Struct.fields) |field, i| {
        bufs[i] = sliceOf(@field(vals, field.name));
    }

    return dst.appendAll(&bufs);
}

test "sizeOfAll" {
    try testing.expectEqual(@as(usize, 32 + 64 + 4), sizeOfAll(.{ @as([32]u8, undefined), @as([64]u8, undefined), @as(u32, undefined) }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), sizeOfAll(.{ [32]u8, [64]u8, u32 }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), sizeOfAll(.{ .sender = [32]u8, .signature = [64]u8, .data_len = u32 }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), sizeOfAll(.{ .sender = [32]u8, .signature = [64]u8, .data_len = @as(u32, 4) }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), sizeOfAll(struct { sender: [32]u8, signature: [64]u8, data_len: u32 }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), sizeOfAll(.{ .sender = [32]u8, .signature = [64]u8, .random_text = "abcd" }));
}

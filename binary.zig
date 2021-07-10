const std = @import("std");

const mem = std.mem;
const meta = std.meta;
const math = std.math;
const testing = std.testing;

const assert = std.debug.assert;

const binary = @This();

pub const Buffer = struct {
    parent: *std.ArrayList(u8),
    offset: usize,
    len: usize,

    /// Wraps an array list into a buffer.
    pub fn from(parent: *std.ArrayList(u8)) binary.Buffer {
        return Buffer{ .parent = parent, .offset = 0, .len = parent.items.len };
    }

    /// Returns a buffer that is a subslice of this buffer.
    pub fn slice(self: binary.Buffer, start: usize, end: usize) binary.Buffer {
        assert(self.offset + start <= self.parent.capacity and self.offset + end <= self.parent.capacity);
        return Buffer{ .parent = self.parent, .offset = self.offset + start, .len = end - start };
    }

    /// Returns a buffer sliced starting from the beginning of this buffer.
    pub fn sliceFromStart(self: binary.Buffer) binary.Buffer {
        return Buffer{ .parent = self.parent, .offset = self.offset, .len = 0 };
    }

    /// Returns a buffer sliced starting from the end of this buffer.
    pub fn sliceFromEnd(self: binary.Buffer) binary.Buffer {
        return binary.Buffer{ .parent = self.parent, .offset = self.offset + self.len, .len = 0 };
    }

    /// Returns a ptr to the underlying slice this buffer wraps around.
    pub fn ptr(self: binary.Buffer) [*]u8 {
        return self.parent.items.ptr + self.offset;
    }

    /// Returns the underlying slice this buffer wraps around.
    pub fn items(self: binary.Buffer) []u8 {
        return self.ptr()[0..self.len];
    }

    /// Allocates len bytes to the end of the buffer.
    pub fn allocate(self: binary.Buffer, len: usize) !binary.Buffer {
        try self.parent.ensureTotalCapacity(self.offset + self.len + len);
        self.parent.items.len = math.max(self.parent.items.len, self.offset + self.len + len);
        return binary.Buffer{ .parent = self.parent, .offset = self.offset, .len = self.len + len };
    }

    /// Appends buf to the end of the buffer.
    pub fn append(self: binary.Buffer, buf: []const u8) !binary.Buffer {
        try self.parent.ensureTotalCapacity(self.offset + self.len + buf.len);
        mem.copy(u8, (self.parent.items.ptr + self.offset + self.len)[0..buf.len], buf);
        self.parent.items.len = math.max(self.parent.items.len, self.offset + self.len + buf.len);
        return binary.Buffer{ .parent = self.parent, .offset = self.offset, .len = self.len + buf.len };
    }

    /// Appends multiple bufs to the end of the buffer. Buffers that are passed in may safely
    /// alias with one another. Only performs at most a single std.mem.Allocator.resize operation
    /// when appending multiple buffers in comparison to Buffer.append.
    pub fn appendAll(self: binary.Buffer, bufs: []const []const u8) !binary.Buffer {
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

        self.parent.items.len = math.max(self.parent.items.len, self.offset + len);

        return binary.Buffer{ .parent = self.parent, .offset = self.offset, .len = len };
    }
};

pub fn sizeOf(T: anytype) usize {
    if (comptime @TypeOf(T) != type) {
        if (comptime meta.trait.isZigString(@TypeOf(T))) {
            return T.len;
        }
        return binary.sizeOf(@TypeOf(T));
    }

    if (comptime @typeInfo(T) == .Enum) {
        return @sizeOf(meta.Tag(T));
    } else if (comptime @typeInfo(T) == .Int) {
        return @sizeOf(T);
    } else if (comptime @typeInfo(T) == .Array and @typeInfo(T).Array.child == u8) {
        return @sizeOf(T);
    } else if (comptime meta.trait.isSlice(T)) {
        return 0;
    } else {
        @compileError("Unsupported type '" ++ @typeName(T) ++ "'");
    }
}

pub fn sizeOfAll(T: anytype) usize {
    var size: usize = 0;

    if (comptime @TypeOf(T) == type and @typeInfo(T) == .Struct) {
        inline for (@typeInfo(T).Struct.fields) |field| {
            size += binary.sizeOf(field.field_type);
        }
    } else if (comptime @typeInfo(@TypeOf(T)) == .Struct) {
        inline for (@typeInfo(@TypeOf(T)).Struct.fields) |field| {
            size += binary.sizeOf(@field(T, field.name));
        }
    } else {
        @compileError("Unsupported type '" ++ @typeName(T) ++ "'");
    }

    return size;
}

pub fn allocateAll(dst: Buffer, T: anytype) !Buffer {
    return dst.allocate(binary.sizeOfAll(T));
}

pub fn write(dst: Buffer, val: anytype) !Buffer {
    const T = @TypeOf(val);
    dst.append(if (comptime @typeInfo(T) == .Enum)
        mem.asBytes(&mem.nativeToLittle(meta.Tag(T), @enumToInt(val)))
    else if (comptime @typeInfo(T) == .Int)
        mem.asBytes(&mem.nativeToLittle(T, val))
    else if (comptime @typeInfo(T) == .Array and @typeInfo(T).Array.child == u8)
        &val
    else if (comptime meta.trait.isZigString(T))
        val
    else
        @compileError("Unsupported type '" ++ @typeName(T) ++ "'"));
}

pub fn writeAll(dst: Buffer, vals: anytype) !Buffer {
    comptime assert(meta.trait.is(.Struct)(@TypeOf(vals)));

    var bufs: [@typeInfo(@TypeOf(vals)).Struct.fields.len][]const u8 = undefined;
    inline for (@typeInfo(@TypeOf(vals)).Struct.fields) |field, i| {
        const val = @field(vals, field.name);

        const T = @TypeOf(val);
        bufs[i] = if (comptime @typeInfo(T) == .Enum)
            mem.asBytes(&mem.nativeToLittle(meta.Tag(T), @enumToInt(val)))
        else if (comptime @typeInfo(T) == .Int)
            mem.asBytes(&mem.nativeToLittle(T, val))
        else if (comptime @typeInfo(T) == .Array and @typeInfo(T).Array.child == u8)
            &val
        else if (comptime meta.trait.isZigString(T))
            val
        else
            @compileError("Unsupported type '" ++ @typeName(T) ++ "'");
    }

    return dst.appendAll(&bufs);
}

pub fn decode(comptime T: type, buf: []const u8) !ReturnTypeOf(T) {
    if (comptime @typeInfo(T) == .Enum) {
        if (buf.len < @sizeOf(meta.Tag(T))) return error.ShortRead;
        return meta.intToEnum(T, mem.readIntLittle(meta.Tag(T), buf[0..@sizeOf(meta.Tag(T))]));
    } else if (comptime @typeInfo(T) == .Int) {
        if (buf.len < @sizeOf(T)) return error.ShortRead;
        return mem.readIntLittle(T, buf[0..@sizeOf(T)]);
    } else if (comptime @typeInfo(T) == .Array and @typeInfo(T).Array.child == u8) {
        if (buf.len < @sizeOf(T)) return error.ShortRead;
        return buf[0..@sizeOf(T)].*;
    } else if (comptime meta.trait.isSlice(T)) {
        return mem.bytesAsSlice(meta.Child(T), buf).ptr;
    } else {
        @compileError("Unsupported type '" ++ @typeName(T) ++ "'");
    }
}

pub fn Decoder(comptime Self: type, comptime layout: anytype) type {
    const T = T: {
        if (meta.trait.isTuple(@TypeOf(layout))) {
            var fields: []const std.builtin.TypeInfo.StructField = &[_]std.builtin.TypeInfo.StructField{};
            inline for (layout) |T| fields = fields ++ @typeInfo(T).Struct.fields;

            break :T @Type(.{
                .Struct = .{
                    .is_tuple = false,
                    .layout = .Auto,
                    .decls = &[_]std.builtin.TypeInfo.Declaration{},
                    .fields = fields,
                },
            });
        } else if (@TypeOf(layout) == type and @typeInfo(layout) == .Struct) {
            break :T layout;
        } else {
            @compileError("Unsupported layout type '" ++ @typeName(@TypeOf(layout)) ++ "'");
        }
    };

    return struct {
        pub fn get(self: Self, comptime field: meta.FieldEnum(T)) binary.ReturnTypeOf(meta.fieldInfo(T, field).field_type) {
            return self.tryGet(field) catch unreachable;
        }

        pub fn tryGet(self: Self, comptime field: meta.FieldEnum(T)) !binary.ReturnTypeOf(meta.fieldInfo(T, field).field_type) {
            comptime var size = 0;

            comptime var index = 0;
            inline while (index < @enumToInt(field)) : (index += 1) {
                comptime size += binary.sizeOf(@typeInfo(T).Struct.fields[index].field_type);
            }

            return binary.decode(meta.fieldInfo(T, field).field_type, self.buffer[size..]);
        }
    };
}

pub fn ReturnTypeOf(comptime T: type) type {
    if (meta.trait.isSlice(T)) {
        return @Type(.{ .Pointer = .{
            .size = .Many,
            .is_const = true,
            .is_volatile = false,
            .alignment = @alignOf(meta.Child(T)),
            .child = meta.Child(T),
            .is_allowzero = false,
            .sentinel = null,
        } });
    }
    return T;
}

test "binary: sizeOfAll" {
    try testing.expectEqual(@as(usize, 32 + 64 + 4), binary.sizeOfAll(.{ @as([32]u8, undefined), @as([64]u8, undefined), @as(u32, undefined) }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), binary.sizeOfAll(.{ [32]u8, [64]u8, u32 }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), binary.sizeOfAll(.{ .sender = [32]u8, .signature = [64]u8, .data_len = u32 }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), binary.sizeOfAll(.{ .sender = [32]u8, .signature = [64]u8, .data_len = @as(u32, 4) }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), binary.sizeOfAll(struct { sender: [32]u8, signature: [64]u8, data_len: u32 }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), binary.sizeOfAll(.{ .sender = [32]u8, .signature = [64]u8, .random_text = "abcd" }));
}

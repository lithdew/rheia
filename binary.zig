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

    /// Ensures there is some specified amount of unused capacity available at the end of
    /// this buffer.
    pub fn ensureUnusedCapacity(self: binary.Buffer, size: usize) !void {
        try self.parent.ensureTotalCapacity(self.offset + self.len + size);
    }

    /// Allocates len bytes to the end of the buffer.
    pub fn allocate(self: binary.Buffer, len: usize) !binary.Buffer {
        try self.ensureUnusedCapacity(len);
        self.parent.items.len = math.max(self.parent.items.len, self.offset + self.len + len);
        return binary.Buffer{ .parent = self.parent, .offset = self.offset, .len = self.len + len };
    }

    /// Appends buf to the end of the buffer.
    pub fn append(self: binary.Buffer, buf: []const u8) !binary.Buffer {
        try self.ensureUnusedCapacity(buf.len);
        return self.appendAssumeCapacity(buf);
    }

    /// Appends buf to the end of the buffer.
    pub fn appendAssumeCapacity(self: binary.Buffer, buf: []const u8) binary.Buffer {
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

        try self.ensureUnusedCapacity(size);

        var len = self.len;
        for (bufs) |buf| {
            mem.copy(u8, (self.parent.items.ptr + self.offset + len)[0..buf.len], buf);
            len += buf.len;
        }

        self.parent.items.len = math.max(self.parent.items.len, self.offset + len);

        return binary.Buffer{ .parent = self.parent, .offset = self.offset, .len = len };
    }
};

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
        pub fn get(self: Self, comptime field: meta.FieldEnum(T)) meta.fieldInfo(T, field).field_type {
            return self.tryGet(field) catch unreachable;
        }

        pub fn tryGet(self: Self, comptime field: meta.FieldEnum(T)) !meta.fieldInfo(T, field).field_type {
            const size = comptime size: {
                var size: usize = 0;
                var index: usize = 0;
                while (index < @enumToInt(field)) : (index += 1) {
                    size += binary.sizeOf(@typeInfo(T).Struct.fields[index].field_type);
                }
                break :size size;
            };

            return binary.decode(meta.fieldInfo(T, field).field_type, self.buffer[size..]);
        }
    };
}

pub fn StructSlice(comptime T: type, comptime start: meta.FieldEnum(T), comptime end: meta.FieldEnum(T)) type {
    var info = @typeInfo(T);
    info.Struct.fields = info.Struct.fields[@enumToInt(start) .. @enumToInt(end) + 1];
    return @Type(info);
}

pub fn allocate(dst: Buffer, T: anytype) !Buffer {
    return dst.allocate(binary.sizeOf(T));
}

pub fn write(dst: Buffer, val: anytype) !Buffer {
    try dst.ensureUnusedCapacity(binary.sizeOf(val));
    return binary.writeAssumeCapacity(dst, val);
}

pub fn writeAssumeCapacity(dst: Buffer, val: anytype) Buffer {
    const T = @TypeOf(val);

    if (comptime @typeInfo(T) == .Struct) {
        var result = dst;
        inline for (@typeInfo(T).Struct.fields) |field| {
            result = binary.writeAssumeCapacity(result, @field(val, field.name));
        }
        return result;
    } else if (comptime @typeInfo(T) == .Optional) {
        if (val) |v| {
            var result = binary.writeAssumeCapacity(dst, true);
            return binary.writeAssumeCapacity(result, v);
        }
        return binary.writeAssumeCapacity(dst, false);
    } else if (comptime @typeInfo(T) == .Int) {
        return dst.appendAssumeCapacity(mem.asBytes(&mem.nativeToLittle(T, val)));
    } else if (comptime @typeInfo(T) == .Bool) {
        return dst.appendAssumeCapacity(mem.asBytes(&@as(u8, if (val) 1 else 0)));
    } else if (comptime @typeInfo(T) == .Enum) {
        return dst.appendAssumeCapacity(mem.asBytes(&mem.nativeToLittle(meta.Tag(T), @enumToInt(val))));
    } else if (comptime @typeInfo(T) == .Array and meta.trait.hasUniqueRepresentation(meta.Child(T))) {
        return dst.appendAssumeCapacity(mem.sliceAsBytes(&val));
    } else if (comptime meta.trait.isPtrTo(.Array)(T) and meta.trait.hasUniqueRepresentation(meta.Elem(T))) {
        return dst.appendAssumeCapacity(mem.sliceAsBytes(val));
    } else if (comptime meta.trait.isSlice(T) and meta.trait.hasUniqueRepresentation(meta.Child(T))) {
        return dst.appendAssumeCapacity(mem.sliceAsBytes(val));
    } else {
        @compileError("Unsupported type '" ++ @typeName(T) ++ "'");
    }
}

pub fn decode(comptime T: type, buf: []const u8) !T {
    if (buf.len < binary.sizeOf(T)) {
        return error.ShortBuffer;
    }

    if (comptime @typeInfo(T) == .Struct) {
        var result: T = undefined;
        var bytes_read: usize = 0;
        inline for (@typeInfo(T).Struct.fields) |field| {
            @field(result, field.name) = try binary.decode(field.field_type, buf[bytes_read..]);
            bytes_read += binary.sizeOf(field.field_type);
        }
        return result;
    } else if (comptime @typeInfo(T) == .Optional) {
        if (try binary.decode(bool, buf)) {
            return try binary.decode(meta.Child(T), buf[binary.sizeOf(bool)..]);
        }
        return null;
    } else if (comptime @typeInfo(T) == .Int) {
        return mem.readIntLittle(T, buf[0..comptime binary.sizeOf(T)]);
    } else if (comptime @typeInfo(T) == .Bool) {
        return buf[0] != 0;
    } else if (comptime @typeInfo(T) == .Enum) {
        return meta.intToEnum(T, mem.readIntLittle(meta.Tag(T), buf[0..@sizeOf(meta.Tag(T))]));
    } else if (comptime @typeInfo(T) == .Array and meta.trait.hasUniqueRepresentation(meta.Child(T))) {
        return mem.bytesToValue(T, buf[0..comptime binary.sizeOf(T)]);
    } else if (comptime meta.trait.isPtrTo(.Array)(T) and meta.trait.hasUniqueRepresentation(meta.Elem(T))) {
        return mem.bytesAsValue(T, buf[0..comptime binary.sizeOf(T)]);
    } else if (comptime meta.trait.isSlice(T) and meta.trait.hasUniqueRepresentation(meta.Child(T))) {
        if (buf.len % binary.sizeOf(meta.Child(T)) != 0) return error.ShortBuffer;
        return mem.bytesAsSlice(meta.Child(T), buf);
    } else {
        @compileError("Unsupported type '" ++ @typeName(T) ++ "'");
    }
}

pub fn sizeOf(T: anytype) usize {
    if (comptime @TypeOf(T) != type) {
        if (comptime @typeInfo(@TypeOf(T)) == .Struct) {
            var size: usize = 0;
            inline for (@typeInfo(@TypeOf(T)).Struct.fields) |field| {
                size += binary.sizeOf(@field(T, field.name));
            }
            return size;
        } else if (comptime @typeInfo(@TypeOf(T)) == .Optional) {
            var size: usize = binary.sizeOf(bool);
            if (T) |v| size += binary.sizeOf(v);
            return size;
        } else if (comptime meta.trait.isSlice(@TypeOf(T)) and meta.trait.hasUniqueRepresentation(meta.Child(@TypeOf(T)))) {
            return T.len * binary.sizeOf(meta.Child(@TypeOf(T)));
        }
        return binary.sizeOf(@TypeOf(T));
    }

    if (comptime @typeInfo(T) == .Struct) {
        return comptime size: {
            var size: usize = 0;
            inline for (@typeInfo(T).Struct.fields) |field| {
                size += binary.sizeOf(field.field_type);
            }
            break :size size;
        };
    } else if (comptime @typeInfo(T) == .Optional) {
        return binary.sizeOf(bool) + binary.sizeOf(meta.Child(T));
    } else if (comptime @typeInfo(T) == .Int) {
        return @sizeOf(T);
    } else if (comptime @typeInfo(T) == .Bool) {
        return @sizeOf(u8);
    } else if (comptime @typeInfo(T) == .Enum) {
        return @sizeOf(meta.Tag(T));
    } else if (comptime @typeInfo(T) == .Array and meta.trait.hasUniqueRepresentation(meta.Child(T))) {
        return @typeInfo(T).Array.len * binary.sizeOf(meta.Child(T));
    } else if (comptime meta.trait.isPtrTo(.Array)(T) and meta.trait.hasUniqueRepresentation(meta.Elem(T))) {
        return @typeInfo(meta.Child(T)).Array.len * binary.sizeOf(meta.Elem(T));
    } else {
        @compileError("Unsupported type '" ++ @typeName(T) ++ "'");
    }
}

test "binary: sizeOf" {
    try testing.expectEqual(@as(usize, 32 + 64 + 4), binary.sizeOf(.{ @as([32]u8, undefined), @as([64]u8, undefined), @as(u32, undefined) }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), binary.sizeOf(.{ [32]u8, [64]u8, u32 }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), binary.sizeOf(.{ .sender = [32]u8, .signature = [64]u8, .data_len = u32 }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), binary.sizeOf(.{ .sender = [32]u8, .signature = [64]u8, .data_len = @as(u32, 4) }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), binary.sizeOf(struct { sender: [32]u8, signature: [64]u8, data_len: u32 }));
    try testing.expectEqual(@as(usize, 32 + 64 + 4), binary.sizeOf(.{ .sender = [32]u8, .signature = [64]u8, .random_text = "abcd" }));
}

test "binary: optional" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    const data = try binary.write(binary.Buffer.from(&buf), .{ .a = @as(?u64, 123) });

    try testing.expectEqual(data.len, binary.sizeOf(.{ .a = @as(?u64, 123) }));
    try testing.expectEqual(try binary.decode(?u64, data.items()), @as(?u64, 123));
}

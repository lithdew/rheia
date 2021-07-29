const std = @import("std");

const io = std.io;
const mem = std.mem;
const crypto = std.crypto;

const Ed25519 = std.crypto.sign.Ed25519;
const Sha512 = std.crypto.hash.sha2.Sha512;

pub fn HashWriter(comptime T: type) type {
    return struct {
        pub const Writer = io.Writer(*Self, ErrorSetOf(Self.write), Self.write);

        const Self = @This();

        state: T,

        fn ErrorSetOf(comptime F: anytype) type {
            return @typeInfo(@typeInfo(@TypeOf(F)).Fn.return_type.?).ErrorUnion.error_set;
        }

        pub fn wrap(state: T) Self {
            return Self{ .state = state };
        }

        pub fn writer(self: *Self) Self.Writer {
            return .{ .context = self };
        }

        pub fn digest(self: *Self, comptime num_bytes: comptime_int) [num_bytes]u8 {
            var bytes: [num_bytes]u8 = undefined;
            self.state.final(&bytes);
            return bytes;
        }

        fn write(self: *Self, buffer: []const u8) !usize {
            self.state.update(buffer);
            return buffer.len;
        }
    };
}

pub fn sign(item: anytype, keys: Ed25519.KeyPair) ![Ed25519.signature_length]u8 {
    var az = az: {
        var hash = HashWriter(Sha512).wrap(Sha512.init(.{}));
        try hash.writer().writeAll(keys.secret_key[0..Ed25519.seed_length]);
        break :az hash.digest(Sha512.digest_length);
    };

    const nonce = nonce: {
        var hash = HashWriter(Sha512).wrap(Sha512.init(.{}));
        try hash.writer().writeAll(az[32..]);
        try item.writeSignaturePayload(hash.writer());
        break :nonce Ed25519.Curve.scalar.reduce64(hash.digest(Sha512.digest_length));
    };

    const point = try Ed25519.Curve.basePoint.mul(nonce);

    var signature: [Ed25519.signature_length]u8 = undefined;
    mem.copy(u8, signature[0..32], &point.toBytes());
    mem.copy(u8, signature[32..], &keys.public_key);

    var hram = hram: {
        var hash = HashWriter(Sha512).wrap(Sha512.init(.{}));
        try hash.writer().writeAll(&signature);
        try item.writeSignaturePayload(hash.writer());
        break :hram Ed25519.Curve.scalar.reduce64(hash.digest(Sha512.digest_length));
    };

    Ed25519.Curve.scalar.clamp(az[0..32]);

    const s = Ed25519.Curve.scalar.mulAdd(hram, az[0..32].*, nonce);
    mem.copy(u8, signature[32..], &s);

    return signature;
}

pub fn verify(signature: [Ed25519.signature_length]u8, item: anytype, public_key: [Ed25519.public_length]u8) !void {
    try Ed25519.Curve.scalar.rejectNonCanonical(signature[32..64].*);
    try Ed25519.Curve.rejectNonCanonical(public_key);

    const a = try Ed25519.Curve.fromBytes(public_key);
    try a.rejectIdentity();

    try Ed25519.Curve.rejectNonCanonical(signature[0..32].*);

    const expected = try Ed25519.Curve.fromBytes(signature[0..32].*);
    try expected.rejectIdentity();

    const hram = hram: {
        var hash = HashWriter(Sha512).wrap(Sha512.init(.{}));
        try hash.writer().writeAll(signature[0..32]);
        try hash.writer().writeAll(&public_key);
        try item.writeSignaturePayload(hash.writer());
        break :hram Ed25519.Curve.scalar.reduce64(hash.digest(Sha512.digest_length));
    };

    var point = try Ed25519.Curve.basePoint.mulDoubleBasePublic(signature[32..64].*, a.neg(), hram);
    if (expected.sub(point).clearCofactor().rejectIdentity() catch null != null) {
        return error.SignatureVerificationFailed;
    }
}

pub fn verifyBatch(items: anytype) !void {
    var r_batch: [items.len][32]u8 = undefined;
    var s_batch: [items.len][32]u8 = undefined;
    var a_batch: [items.len]Ed25519.Curve = undefined;
    var expected_batch: [items.len]Ed25519.Curve = undefined;

    for (items) |item, i| {
        try Ed25519.Curve.scalar.rejectNonCanonical(item.signature[32..64].*);
        try Ed25519.Curve.rejectNonCanonical(item.sender);

        var a = try Ed25519.Curve.fromBytes(item.sender);
        try a.rejectIdentity();

        try Ed25519.Curve.rejectNonCanonical(item.signature[0..32].*);

        var expected = try Ed25519.Curve.fromBytes(item.signature[0..32].*);
        try expected.rejectIdentity();

        expected_batch[i] = expected;
        r_batch[i] = item.signature[0..32].*;
        s_batch[i] = item.signature[32..64].*;
        a_batch[i] = a;
    }

    var hram_batch: [items.len]Ed25519.Curve.scalar.CompressedScalar = undefined;
    for (items) |item, i| {
        var hash = HashWriter(Sha512).wrap(Sha512.init(.{}));
        try hash.writer().writeAll(r_batch[i][0..32]);
        try hash.writer().writeAll(&item.sender);
        try item.writeSignaturePayload(hash.writer());
        hram_batch[i] = Ed25519.Curve.scalar.reduce64(hash.digest(Sha512.digest_length));
    }

    var z_batch: [items.len]Ed25519.Curve.scalar.CompressedScalar = undefined;
    for (z_batch) |*z| {
        crypto.random.bytes(z[0..16]);
        mem.set(u8, z[16..], 0);
    }

    var zs_sum = Ed25519.Curve.scalar.zero;
    for (z_batch) |z, i| {
        zs_sum = Ed25519.Curve.scalar.mulAdd(z, s_batch[i], zs_sum);
    }
    zs_sum = Ed25519.Curve.scalar.mul8(zs_sum);

    var zhs: [items.len]Ed25519.Curve.scalar.CompressedScalar = undefined;
    for (z_batch) |z, i| {
        zhs[i] = Ed25519.Curve.scalar.mul(z, hram_batch[i]);
    }

    const zr = (try Ed25519.Curve.mulMulti(items.len, expected_batch, z_batch)).clearCofactor();
    const zah = (try Ed25519.Curve.mulMulti(items.len, a_batch, zhs)).clearCofactor();

    const zsb = try Ed25519.Curve.basePoint.mulPublic(zs_sum);
    if (zr.add(zah).sub(zsb).rejectIdentity() catch null != null) {
        return error.SignatureVerificationFailed;
    }
}

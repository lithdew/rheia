const std = @import("std");

const sort = std.sort;
const ascii = std.ascii;

pub fn CaseInsensitiveStringMap(comptime V: type, comptime kvs: anytype) type {
    const precomputed = comptime blk: {
        @setEvalBranchQuota(100_000);

        const KV = struct {
            key: []const u8,
            value: V,

            fn lessThan(_: void, a: @This(), b: @This()) bool {
                return a.key.len < b.key.len;
            }
        };

        var sorted_kvs: [kvs.len]KV = undefined;
        for (kvs) |kv, i| {
            if (V != void) {
                sorted_kvs[i] = .{ .key = kv[0], .value = kv[1] };
            } else {
                sorted_kvs[i] = .{ .key = kv[0], .value = {} };
            }
        }

        sort.sort(KV, &sorted_kvs, {}, KV.lessThan);

        const min_len = sorted_kvs[0].key.len;
        const max_len = sorted_kvs[sorted_kvs.len - 1].key.len;

        var len_indices: [max_len + 1]usize = undefined;
        var len: usize = 0;
        var i: usize = 0;

        while (len <= max_len) : (len += 1) {
            while (len > sorted_kvs[i].key.len) {
                i += 1;
            }
            len_indices[len] = i;
        }

        break :blk .{
            .min_len = min_len,
            .max_len = max_len,
            .sorted_kvs = sorted_kvs,
            .len_indices = len_indices,
        };
    };

    return struct {
        pub fn has(str: []const u8) bool {
            return get(str) != null;
        }

        pub fn get(val: V) ?[]const u8 {
            inline for (kvs) |kv| {
                if (kv[1] == val) {
                    return kv[0];
                }
            }
            return null;
        }

        pub fn parse(str: []const u8) ?V {
            if (str.len < precomputed.min_len or str.len > precomputed.max_len) {
                return null;
            }

            var i = precomputed.len_indices[str.len];
            while (true) {
                const kv = precomputed.sorted_kvs[i];
                if (kv.key.len != str.len) {
                    return null;
                }
                if (ascii.eqlIgnoreCase(kv.key, str)) {
                    return kv.value;
                }
                i += 1;
                if (i >= precomputed.sorted_kvs.len) {
                    return null;
                }
            }
        }
    };
}

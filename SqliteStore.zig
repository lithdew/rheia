const std = @import("std");
const rheia = @import("main.zig");
const sqlite = @import("zig-sqlite/sqlite.zig");

const fs = std.fs;
const mem = std.mem;

const SqliteStore = @This();

const store_block_query = "insert into blocks(id, height, merkle_root, num_transaction_ids) values (?{[]const u8}, ?{u64}, ?{[]const u8}, ?{u16})";
const store_transaction_query = "insert into transactions(id, block_height, sender, signature, sender_nonce, created_at, tag, data) values (?{[]const u8}, ?{u64}, ?{[]const u8}, ?{[]const u8}, ?{u64}, ?{u64}, ?{[]const u8}, ?{[]const u8})";
const is_transaction_finalized_query = "select 1 from transactions where id = ?{[]const u8}";
const get_blocks_query = "select id, height, merkle_root from blocks order by height desc limit ?{usize} offset ?{usize}";
const get_block_summaries_query = "select id, height, merkle_root, num_transaction_ids from blocks order by height desc limit ?{usize} offset ?{usize}";
const get_block_by_id_query = "select height, merkle_root from blocks where id = ?{[]const u8}";
const get_block_by_height_query = "select id, merkle_root from blocks where height = ?{u64}";
const get_transactions_query = "select id, sender, signature, sender_nonce, created_at, tag, data from transactions order by block_height desc limit ?{usize} offset ?{usize}";
const get_transaction_by_id_query = "select id, sender, signature, sender_nonce, created_at, tag, data from transactions where id = ?";
const get_transaction_ids_by_block_height_query = "select id from transactions where block_height = ?{u64}";
const get_transactions_by_block_height_query = "select id, sender, signature, sender_nonce, created_at, tag, data from transactions where block_height = ?{u64} limit ?{usize} offset ?{usize}";
const is_whitelist_filled_query = "select 1 from whitelist";
const is_public_key_whitelisted_query = "select 1 from whitelist where public_key = ?{[]const u8}";
const add_public_key_to_whitelist_query = "insert or ignore into whitelist(public_key) values (?{[]const u8})";
const remove_public_key_from_whitelist_query = "delete from whitelist where public_key = ?{[]const u8}";

pub const PooledConnection = struct {};

pub const Authorizer = struct {
    pub fn check(
        user_data: ?*anyopaque,
        action_code: c_int,
        param_1: ?[*:0]const u8,
        param_2: ?[*:0]const u8,
        param_3: ?[*:0]const u8,
        param_4: ?[*:0]const u8,
    ) callconv(.C) c_int {
        _ = user_data;
        _ = param_2;
        _ = param_3;
        _ = param_4;

        switch (action_code) {
            sqlite.c.SQLITE_DELETE => {
                const table_name = mem.sliceTo(param_1 orelse return sqlite.c.SQLITE_OK, 0);
                if (mem.eql(u8, table_name, "blocks") or
                    mem.eql(u8, table_name, "transactions"))
                {
                    return sqlite.c.SQLITE_DENY;
                }
            },
            sqlite.c.SQLITE_UPDATE,
            sqlite.c.SQLITE_DROP_TABLE,
            => {
                const table_name = mem.sliceTo(param_1 orelse return sqlite.c.SQLITE_OK, 0);
                if (mem.eql(u8, table_name, "blocks") or
                    mem.eql(u8, table_name, "transactions") or
                    mem.eql(u8, table_name, "whitelist"))
                {
                    return sqlite.c.SQLITE_DENY;
                }
            },
            else => {},
        }

        return sqlite.c.SQLITE_OK;
    }
};

const log = std.log.scoped(.sqlite);

conn: sqlite.Db,
maybe_path: ?[]const u8,

store_block: sqlite.StatementType(.{}, store_block_query),
store_transaction: sqlite.StatementType(.{}, store_transaction_query),
is_transaction_finalized: sqlite.StatementType(.{}, is_transaction_finalized_query),
get_blocks: sqlite.StatementType(.{}, get_blocks_query),
get_block_summaries: sqlite.StatementType(.{}, get_block_summaries_query),
get_block_by_id: sqlite.StatementType(.{}, get_block_by_id_query),
get_block_by_height: sqlite.StatementType(.{}, get_block_by_height_query),
get_transactions: sqlite.StatementType(.{}, get_transactions_query),
get_transaction_by_id: sqlite.StatementType(.{}, get_transaction_by_id_query),
get_transaction_ids_by_block_height: sqlite.StatementType(.{}, get_transaction_ids_by_block_height_query),
get_transactions_by_block_height: sqlite.StatementType(.{}, get_transactions_by_block_height_query),
is_whitelist_filled: sqlite.StatementType(.{}, is_whitelist_filled_query),
is_public_key_whitelisted: sqlite.StatementType(.{}, is_public_key_whitelisted_query),
add_public_key_to_whitelist: sqlite.StatementType(.{}, add_public_key_to_whitelist_query),
remove_public_key_from_whitelist: sqlite.StatementType(.{}, remove_public_key_from_whitelist_query),

pub fn init(_: mem.Allocator, maybe_path: ?[]const u8) !SqliteStore {
    var diags: sqlite.Diagnostics = .{};
    errdefer |err| log.warn("failed to create sqlite connection to '{s}' ({}): {}", .{ maybe_path, err, diags });

    var conn: sqlite.Db = db: {
        const path = maybe_path orelse {
            break :db try sqlite.Db.init(.{
                .mode = .{ .File = "file:rheia?mode=memory" },
                .open_flags = .{ .create = true, .write = true },
                .threading_mode = .Serialized,
                .shared_cache = true,
                .diags = &diags,
            });
        };

        var path_buf: [fs.MAX_PATH_BYTES]u8 = undefined;
        mem.copy(u8, &path_buf, path);
        path_buf[path.len] = 0;

        break :db try sqlite.Db.init(.{
            .mode = .{ .File = path_buf[0..path.len :0] },
            .open_flags = .{ .create = true, .write = true },
            .threading_mode = .Serialized,
            .shared_cache = true,
            .diags = &diags,
        });
    };
    errdefer conn.deinit();

    var error_message: [*c]u8 = null;
    defer if (error_message) |error_message_ptr| {
        log.warn("failed to init schema: {s}", .{error_message_ptr});
        sqlite.c.sqlite3_free(error_message_ptr);
    };

    if (sqlite.c.sqlite3_exec(conn.db, @embedFile("schema.sql"), null, null, &error_message) != sqlite.c.SQLITE_OK) {
        return error.SQLiteError;
    }

    _ = try conn.pragma(void, .{}, "page_size", "32768");
    _ = try conn.pragma(void, .{}, "journal_mode", "WAL");
    // _ = try conn.pragma(void, .{}, "read_uncommitted", "true");
    // _ = try conn.pragma(void, .{}, "synchronous", "off");
    _ = try conn.pragma(void, .{}, "temp_store", "memory");
    _ = try conn.pragma(void, .{}, "mmap_size", "30000000000");

    var store_block = try conn.prepareWithDiags(store_block_query, .{ .diags = &diags });
    errdefer store_block.deinit();

    var store_transaction = try conn.prepareWithDiags(store_transaction_query, .{ .diags = &diags });
    errdefer store_transaction.deinit();

    var is_transaction_finalized = try conn.prepareWithDiags(is_transaction_finalized_query, .{ .diags = &diags });
    errdefer is_transaction_finalized.deinit();

    var get_blocks = try conn.prepareWithDiags(get_blocks_query, .{ .diags = &diags });
    errdefer get_blocks.deinit();

    var get_block_summaries = try conn.prepareWithDiags(get_block_summaries_query, .{ .diags = &diags });
    errdefer get_block_summaries.deinit();

    var get_block_by_id = try conn.prepareWithDiags(get_block_by_id_query, .{ .diags = &diags });
    errdefer get_block_by_id.deinit();

    var get_block_by_height = try conn.prepareWithDiags(get_block_by_height_query, .{ .diags = &diags });
    errdefer get_block_by_height.deinit();

    var get_transactions = try conn.prepareWithDiags(get_transactions_query, .{ .diags = &diags });
    errdefer get_transactions.deinit();

    var get_transaction_by_id = try conn.prepareWithDiags(get_transaction_by_id_query, .{ .diags = &diags });
    errdefer get_transaction_by_id.deinit();

    var get_transaction_ids_by_block_height = try conn.prepareWithDiags(get_transaction_ids_by_block_height_query, .{ .diags = &diags });
    errdefer get_transaction_ids_by_block_height.deinit();

    var get_transactions_by_block_height = try conn.prepareWithDiags(get_transactions_by_block_height_query, .{ .diags = &diags });
    errdefer get_transactions_by_block_height.deinit();

    var is_whitelist_filled = try conn.prepareWithDiags(is_whitelist_filled_query, .{ .diags = &diags });
    errdefer is_whitelist_filled.deinit();

    var is_public_key_whitelisted = try conn.prepareWithDiags(is_public_key_whitelisted_query, .{ .diags = &diags });
    errdefer is_public_key_whitelisted.deinit();

    var add_public_key_to_whitelist = try conn.prepareWithDiags(add_public_key_to_whitelist_query, .{ .diags = &diags });
    errdefer add_public_key_to_whitelist.deinit();

    var remove_public_key_from_whitelist = try conn.prepareWithDiags(remove_public_key_from_whitelist_query, .{ .diags = &diags });
    errdefer remove_public_key_from_whitelist.deinit();

    if (sqlite.c.sqlite3_set_authorizer(conn.db, Authorizer.check, null) != sqlite.c.SQLITE_OK) {
        return error.AuthorizerNotInitialized;
    }

    return SqliteStore{
        .conn = conn,
        .maybe_path = maybe_path,

        .store_block = store_block,
        .store_transaction = store_transaction,
        .is_transaction_finalized = is_transaction_finalized,
        .get_blocks = get_blocks,
        .get_block_summaries = get_block_summaries,
        .get_block_by_id = get_block_by_id,
        .get_block_by_height = get_block_by_height,
        .get_transactions = get_transactions,
        .get_transaction_by_id = get_transaction_by_id,
        .get_transaction_ids_by_block_height = get_transaction_ids_by_block_height,
        .get_transactions_by_block_height = get_transactions_by_block_height,
        .is_whitelist_filled = is_whitelist_filled,
        .is_public_key_whitelisted = is_public_key_whitelisted,
        .add_public_key_to_whitelist = add_public_key_to_whitelist,
        .remove_public_key_from_whitelist = remove_public_key_from_whitelist,
    };
}

pub fn deinit(self: *SqliteStore) void {
    self.store_block.deinit();
    self.store_transaction.deinit();
    self.is_transaction_finalized.deinit();
    self.get_blocks.deinit();
    self.get_block_summaries.deinit();
    self.get_block_by_id.deinit();
    self.get_block_by_height.deinit();
    self.get_transactions.deinit();
    self.get_transaction_by_id.deinit();
    self.get_transaction_ids_by_block_height.deinit();
    self.get_transactions_by_block_height.deinit();
    self.is_whitelist_filled.deinit();
    self.is_public_key_whitelisted.deinit();
    self.add_public_key_to_whitelist.deinit();
    self.remove_public_key_from_whitelist.deinit();
    self.conn.deinit();
}

pub fn acquireConnection(_: *SqliteStore) !PooledConnection {
    return PooledConnection{};
}

pub fn releaseConnection(_: *SqliteStore, _: *PooledConnection) void {}

fn execute(gpa: mem.Allocator, conn: sqlite.Db, raw_query: []const u8) !void {
    var error_message: [*c]u8 = null;
    defer if (error_message) |error_message_ptr| {
        log.warn("error while executing query: {s}", .{error_message_ptr});
        sqlite.c.sqlite3_free(error_message_ptr);
    };

    const query = try std.cstr.addNullByte(gpa, raw_query);
    defer gpa.free(query);

    if (sqlite.c.sqlite3_exec(conn.db, query.ptr, null, null, &error_message) != sqlite.c.SQLITE_OK) {
        return error.SQLiteError;
    }
}

pub fn queryJson(self: *SqliteStore, gpa: mem.Allocator, _: *PooledConnection, raw_query: []const u8) ![]const u8 {
    var diags: sqlite.Diagnostics = .{};
    errdefer |err| log.warn("error while querying json ({}): {}", .{ diags, err });

    var buffer = std.ArrayList(u8).init(gpa);
    defer buffer.deinit();

    var stream = std.json.writeStream(buffer.writer(), 128);

    var stmt = try self.conn.prepareDynamicWithDiags(raw_query, .{ .diags = &diags });
    defer stmt.deinit();

    if (sqlite.c.sqlite3_stmt_readonly(stmt.stmt) == 0) {
        return error.QueryNotReadOnly;
    }

    var count: usize = 0;

    try stream.beginObject();

    try stream.objectField("results");
    try stream.beginArray();

    while (true) {
        const result = sqlite.c.sqlite3_step(stmt.stmt);
        switch (result) {
            sqlite.c.SQLITE_DONE => break,
            sqlite.c.SQLITE_ROW => {},
            else => {
                diags.err = self.conn.getDetailedError();
                return @import("zig-sqlite/errors.zig").errorFromResultCode(result);
            },
        }

        try stream.arrayElem();
        try stream.beginObject();

        var i: c_int = 0;
        while (i < sqlite.c.sqlite3_column_count(stmt.stmt)) : (i += 1) {
            const column_name = sqlite.c.sqlite3_column_name(stmt.stmt, i) orelse return error.OutOfMemory;
            try stream.objectField(mem.sliceTo(column_name, 0));
            switch (sqlite.c.sqlite3_column_type(stmt.stmt, i)) {
                sqlite.c.SQLITE_INTEGER => {
                    try stream.emitNumber(sqlite.c.sqlite3_column_int64(stmt.stmt, i));
                },
                sqlite.c.SQLITE_FLOAT => {
                    try stream.emitNumber(sqlite.c.sqlite3_column_double(stmt.stmt, i));
                },
                sqlite.c.SQLITE_TEXT => {
                    const num_bytes = @intCast(usize, sqlite.c.sqlite3_column_bytes(stmt.stmt, i));
                    try stream.emitJson(.{ .String = sqlite.c.sqlite3_column_text(stmt.stmt, i)[0..num_bytes] });
                },
                sqlite.c.SQLITE_BLOB => {
                    const num_bytes = @intCast(usize, sqlite.c.sqlite3_column_bytes(stmt.stmt, i));
                    try stream.emitJson(.{ .String = sqlite.c.sqlite3_column_text(stmt.stmt, i)[0..num_bytes] });
                },
                sqlite.c.SQLITE_NULL => {
                    try stream.emitNull();
                },
                else => unreachable,
            }
        }

        try stream.endObject();

        count += 1;

        if (buffer.items.len > 1 * 1024 * 1024) {
            break;
        }
    }

    try stream.endArray();

    try stream.objectField("count");
    try stream.emitNumber(count);

    try stream.endObject();

    return buffer.toOwnedSlice();
}

pub fn storeBlock(self: *SqliteStore, gpa: mem.Allocator, _: *PooledConnection, block: *rheia.Block, transactions: []const *rheia.Transaction) !void {
    var diags: sqlite.Diagnostics = .{};
    errdefer |err| log.warn("error while saving block ({}): {}", .{ diags, err });

    try self.conn.exec("begin", .{ .diags = &diags }, .{});
    errdefer self.conn.exec("rollback", .{ .diags = &diags }, .{}) catch {};

    self.store_block.reset();

    try self.store_block.exec(.{ .diags = &diags }, .{
        .id = @as([]const u8, &block.id),
        .height = block.height,
        .merkle_root = @as([]const u8, &block.merkle_root),
        .num_transaction_ids = block.num_transaction_ids,
    });

    for (transactions) |tx| {
        self.store_transaction.reset();

        try self.store_transaction.exec(
            .{ .diags = &diags },
            .{
                .id = @as([]const u8, &tx.id),
                .block_height = block.height,
                .sender = @as([]const u8, &tx.sender),
                .signature = @as([]const u8, &tx.signature),
                .sender_nonce = tx.sender_nonce,
                .created_at = tx.created_at,
                .tag = tx.tag,
                .data = @as([]const u8, tx.data[0..tx.data_len]),
            },
        );

        switch (tx.tag) {
            .no_op => {},
            .stmt => execute(gpa, self.conn, tx.data[0..tx.data_len]) catch {},
        }
    }

    try self.conn.exec("commit", .{ .diags = &diags }, .{});
}

pub fn isTransactionFinalized(self: *SqliteStore, _: *PooledConnection, id: [32]u8) bool {
    var diags: sqlite.Diagnostics = .{};
    errdefer log.warn("error while checking if transaction is finalized: {}", .{diags});

    self.is_transaction_finalized.reset();

    const result = self.is_transaction_finalized.one(usize, .{ .diags = &diags }, .{ .id = @as([]const u8, &id) }) catch return false;
    return result != null;
}

fn getTransactionIdsByBlockHeight(self: *SqliteStore, gpa: mem.Allocator, block_height: u64) ![]const [32]u8 {
    self.get_transaction_ids_by_block_height.reset();
    return try self.get_transaction_ids_by_block_height.all([32]u8, gpa, .{}, .{ .block_height = block_height });
}

pub fn getBlockSummaries(self: *SqliteStore, gpa: mem.Allocator, _: *PooledConnection, offset: usize, limit: usize) ![]const rheia.Block.Summary {
    var blocks: std.ArrayListUnmanaged(rheia.Block.Summary) = .{};
    defer blocks.deinit(gpa);

    var diags: sqlite.Diagnostics = .{};
    errdefer |err| log.warn("error while fetching block summaries ({}): {}", .{ diags, err });

    self.get_block_summaries.reset();

    var it = try self.get_block_summaries.iterator(rheia.Block.Summary, .{ limit, offset });
    while (try it.next(.{ .diags = &diags })) |summary| {
        try blocks.append(gpa, summary);
    }

    return blocks.toOwnedSlice(gpa);
}

pub fn getBlocks(self: *SqliteStore, gpa: mem.Allocator, _: *PooledConnection, offset: usize, limit: usize) ![]const *rheia.Block {
    var blocks: std.ArrayListUnmanaged(*rheia.Block) = .{};
    defer {
        for (blocks.items) |block| {
            block.deinit(gpa);
        }
        blocks.deinit(gpa);
    }

    var diags: sqlite.Diagnostics = .{};
    errdefer |err| log.warn("error while fetching blocks ({}): {}", .{ diags, err });

    self.get_blocks.reset();

    var it = try self.get_blocks.iterator(struct { id: [32]u8, height: u64, merkle_root: [32]u8 }, .{ limit, offset });
    while (try it.next(.{ .diags = &diags })) |header| {
        const transaction_ids = try self.getTransactionIdsByBlockHeight(gpa, header.height);
        defer gpa.free(transaction_ids);

        const block = try rheia.Block.from(gpa, .{
            .id = header.id,
            .height = header.height,
            .merkle_root = header.merkle_root,
            .transaction_ids = transaction_ids,
        });
        errdefer block.deinit(gpa);

        try blocks.append(gpa, block);
    }

    return blocks.toOwnedSlice(gpa);
}

pub fn getTransactions(self: *SqliteStore, gpa: mem.Allocator, _: *PooledConnection, offset: usize, limit: usize) ![]const *rheia.Transaction {
    var transactions: std.ArrayListUnmanaged(*rheia.Transaction) = .{};
    defer {
        for (transactions.items) |tx| {
            tx.deinit(gpa);
        }
        transactions.deinit(gpa);
    }

    var diags: sqlite.Diagnostics = .{};
    errdefer |err| log.warn("error while fetching transactions ({}): {}", .{ diags, err });

    self.get_transactions.reset();

    var it = try self.get_transactions.iterator(rheia.Transaction.Data, .{ limit, offset });
    while (try it.nextAlloc(gpa, .{ .diags = &diags })) |format| {
        defer gpa.free(format.data);

        const tx = try rheia.Transaction.from(gpa, format);
        errdefer tx.deinit(gpa);

        try transactions.append(gpa, tx);
    }

    return transactions.toOwnedSlice(gpa);
}

pub fn getTransactionsByBlockHeight(self: *SqliteStore, gpa: mem.Allocator, _: *PooledConnection, block_height: u64, offset: usize, limit: usize) ![]const *rheia.Transaction {
    var transactions: std.ArrayListUnmanaged(*rheia.Transaction) = .{};
    defer {
        for (transactions.items) |tx| {
            tx.deinit(gpa);
        }
        transactions.deinit(gpa);
    }

    var diags: sqlite.Diagnostics = .{};
    errdefer |err| log.warn("error while fetching transactions ({}): {}", .{ diags, err });

    self.get_transactions_by_block_height.reset();

    var it = try self.get_transactions_by_block_height.iterator(rheia.Transaction.Data, .{ block_height, limit, offset });
    while (try it.nextAlloc(gpa, .{ .diags = &diags })) |format| {
        defer gpa.free(format.data);

        const tx = try rheia.Transaction.from(gpa, format);
        errdefer tx.deinit(gpa);

        try transactions.append(gpa, tx);
    }

    return transactions.toOwnedSlice(gpa);
}

pub fn getBlockById(self: *SqliteStore, gpa: mem.Allocator, _: *PooledConnection, block_id: [32]u8) !?*rheia.Block {
    var diags: sqlite.Diagnostics = .{};
    errdefer |err| log.warn("error while fetching block by id ({}): {}", .{ diags, err });

    self.get_block_by_id.reset();

    const header = (try self.get_block_by_id.one(struct {
        height: u64,
        merkle_root: [32]u8,
    }, .{ .diags = &diags }, .{ .id = @as([]const u8, &block_id) })) orelse return null;

    const transaction_ids = try self.getTransactionIdsByBlockHeight(gpa, header.height);
    defer gpa.free(transaction_ids);

    return try rheia.Block.from(gpa, .{
        .id = block_id,
        .height = header.height,
        .merkle_root = header.merkle_root,
        .transaction_ids = transaction_ids,
    });
}

pub fn getBlockByHeight(self: *SqliteStore, gpa: mem.Allocator, _: *PooledConnection, height: u64) !?*rheia.Block {
    var diags: sqlite.Diagnostics = .{};
    errdefer |err| log.warn("error while fetching block by height ({}): {}", .{ diags, err });

    self.get_block_by_height.reset();

    const header = (try self.get_block_by_height.one(struct {
        id: [32]u8,
        merkle_root: [32]u8,
    }, .{ .diags = &diags }, .{ .height = height })) orelse return null;

    const transaction_ids = try self.getTransactionIdsByBlockHeight(gpa, height);
    defer gpa.free(transaction_ids);

    return try rheia.Block.from(gpa, .{
        .id = header.id,
        .height = height,
        .merkle_root = header.merkle_root,
        .transaction_ids = transaction_ids,
    });
}

pub fn getTransactionById(self: *SqliteStore, gpa: mem.Allocator, _: *PooledConnection, id: [32]u8) !?*rheia.Transaction {
    var diags: sqlite.Diagnostics = .{};
    errdefer |err| log.warn("error while fetching transaction by id ({}): {}", .{ diags, err });

    self.get_transaction_by_id.reset();

    const format = (try self.get_transaction_by_id.oneAlloc(rheia.Transaction.Data, gpa, .{ .diags = &diags }, .{ .id = @as([]const u8, &id) })) orelse return null;
    defer gpa.free(format.data);

    return try rheia.Transaction.from(gpa, format);
}

pub fn isPublicKeyWhitelisted(self: *SqliteStore, _: *PooledConnection, public_key: [32]u8) bool {
    var diags: sqlite.Diagnostics = .{};
    errdefer log.warn("error while checking if public key is whitelisted: {}", .{diags});

    self.is_whitelist_filled.reset();

    if ((self.is_whitelist_filled.one(usize, .{ .diags = &diags }, .{}) catch return false) == null) {
        return true;
    }

    self.is_public_key_whitelisted.reset();

    if ((self.is_public_key_whitelisted.one(usize, .{ .diags = &diags }, .{ .public_key = @as([]const u8, &public_key) }) catch return false) != null) {
        return true;
    }

    return false;
}

pub fn addPublicKeyToWhitelist(self: *SqliteStore, _: *PooledConnection, public_key: [32]u8) !void {
    var diags: sqlite.Diagnostics = .{};
    errdefer log.warn("error while adding public key to whitelist: {}", .{diags});

    self.add_public_key_to_whitelist.reset();

    try self.add_public_key_to_whitelist.exec(
        .{ .diags = &diags },
        .{ .public_key = @as([]const u8, &public_key) },
    );
}

pub fn removePublicKeyFromWhitelist(self: *SqliteStore, _: *PooledConnection, public_key: [32]u8) bool {
    var diags: sqlite.Diagnostics = .{};
    errdefer log.warn("error while removing public key from whitelist: {}", .{diags});

    self.remove_public_key_from_whitelist.reset();

    self.remove_public_key_from_whitelist.exec(
        .{ .diags = &diags },
        .{ .public_key = @as([]const u8, &public_key) },
    ) catch return false;

    if (self.conn.rowsAffected() == 0) {
        return false;
    }

    return true;
}

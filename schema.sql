create table if not exists blocks (
    id blob primary key,
    height int,
    merkle_root blob,
    num_transaction_ids int
) without rowid;

create table if not exists transactions (
    id blob primary key,
    block_height int,
    sender blob,
    signature blob,
    sender_nonce int,
    created_at int,
    tag text,
    data text
) without rowid;

create table if not exists whitelist (
    public_key blob primary key
) without rowid;

create unique index if not exists blocks_by_height on blocks(height);
create index if not exists transactions_by_block_height on transactions(block_height);
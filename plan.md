# Nostr SIKKA Bot Plan

## Goal

Build a Nostr bot that can:

- watch Nostr relays for tip commands
- credit or send SIKKA to users
- notify users by DM when they receive tips
- let users check balance, load balance, and withdraw funds by messaging the bot

The current repository already has the core SIKKA transaction logic and a SQLite-backed bot. The Nostr bot should reuse the wallet and transaction pieces, but use a safer product model than immediate on-chain sending for every comment.

## Recommended Product Model

### v1

Use a custodial internal ledger.

Flow:

1. Bot reads a valid Nostr tip command.
2. Bot verifies the event and command syntax.
3. Bot debits sender internal balance.
4. Bot credits recipient internal balance.
5. Bot sends recipient a DM.
6. Recipient can withdraw to a SIKKA address by DM command.

This is better than immediate on-chain sends for each tip because:

- recipients may not have a SIKKA address yet
- relay duplication is common
- on-chain sends are slower and cost operational effort
- internal ledger transfers are easier to make atomic and idempotent

### Not recommended for v1

Do not start with direct per-comment on-chain payout.

Do not treat derived per-user keys as if they are user-controlled wallets. If the server holds the seed, the system is custodial regardless of how derivation is done.

## Trust Model

This system is custodial.

- the service holds master wallet material
- the service decides when funds move on-chain
- user balances are ledger balances until withdrawn

Because of that, the implementation must prioritize:

- auditability
- strong idempotency
- replay protection
- rate limiting
- safe key handling

## Nostr Message Model

### Public tip commands

Supported example:

`sikka tip 40000 @npub...`

Or a stricter reply-based variant if needed.

The parser should be strict. Avoid fuzzy natural language matching.

### DM commands

Supported commands should be minimal in v1:

- `help`
- `balance`
- `deposit`
- `withdraw all <address>`
- `withdraw <amount> <address>`
- `address set <address>`

### DM protocol

Prefer NIP-17 style private messaging.

Do not build on NIP-04 for new work unless a library constraint forces it temporarily.

## Idempotency and Replay Protection

Relay duplication is expected. Freshness checks help, but they are not enough by themselves.

### Required rules

1. Verify the Nostr event signature before any processing.
2. Reject stale events older than 60 seconds.
3. Check the event ID against a database table before any money movement.
4. Insert the event ID into durable storage with a unique constraint.
5. If the insert fails because the event already exists, stop immediately.
6. Never allow the same payment-causing event ID to trigger money movement twice.

### Important decision

A 10-minute dedupe cache is useful for noisy relay re-delivery, but it must not be the only protection.

If an event causes a credit, debit, or on-chain payment, the event ID must be kept permanently or for very long retention in a durable table.

### Practical model

Use both:

- short-term seen-event caching for performance and burst duplicate suppression
- durable processed-event records for payment idempotency

## Suggested Database Schema

### `nostr_users`

- `pubkey TEXT PRIMARY KEY`
- `created_at INTEGER NOT NULL`
- `default_withdraw_address TEXT`
- `dm_enabled INTEGER NOT NULL DEFAULT 1`

### `balances`

- `pubkey TEXT PRIMARY KEY`
- `available INTEGER NOT NULL DEFAULT 0`
- `pending INTEGER NOT NULL DEFAULT 0`
- `updated_at INTEGER NOT NULL`

### `processed_events`

- `event_id TEXT PRIMARY KEY`
- `pubkey TEXT NOT NULL`
- `kind INTEGER NOT NULL`
- `relay_url TEXT`
- `status TEXT NOT NULL`
- `created_at INTEGER NOT NULL`
- `processed_at INTEGER NOT NULL`

This table is the durable idempotency boundary.

### `tips`

- `event_id TEXT PRIMARY KEY`
- `sender_pubkey TEXT NOT NULL`
- `recipient_pubkey TEXT NOT NULL`
- `amount INTEGER NOT NULL`
- `status TEXT NOT NULL`
- `created_at INTEGER NOT NULL`

### `withdrawals`

- `id INTEGER PRIMARY KEY AUTOINCREMENT`
- `request_event_id TEXT UNIQUE`
- `pubkey TEXT NOT NULL`
- `address TEXT NOT NULL`
- `amount INTEGER NOT NULL`
- `txid TEXT`
- `status TEXT NOT NULL`
- `created_at INTEGER NOT NULL`
- `updated_at INTEGER NOT NULL`

### `dm_outbox`

- `id INTEGER PRIMARY KEY AUTOINCREMENT`
- `recipient_pubkey TEXT NOT NULL`
- `message_type TEXT NOT NULL`
- `payload TEXT NOT NULL`
- `status TEXT NOT NULL`
- `created_at INTEGER NOT NULL`

## Processing Rules

### Tip processing

1. Receive event from relay.
2. Verify signature and parse content.
3. Reject if event is older than 60 seconds.
4. Insert `event_id` into `processed_events` with status `received`.
5. If insert fails because it already exists, stop.
6. Validate sender balance.
7. In one database transaction:
   - create the `tips` row
   - debit sender balance
   - credit recipient balance
   - update processed status to `credited`
8. Queue recipient DM.

### Withdrawal processing

1. Receive DM command.
2. Verify signature and freshness.
3. Insert request event into `processed_events`.
4. If already present, stop.
5. Validate amount and address.
6. Reserve or debit balance in a database transaction.
7. Build and submit SIKKA transaction.
8. Mark withdrawal record with `txid` and final status.
9. Queue result DM.

## Abuse Controls

### Required for v1

- relay allowlist
- strict command parsing
- minimum and maximum tip amount
- per-user rate limits
- withdrawal cooldowns if needed
- exact-match idempotency on event ID
- logging for all credits, debits, and withdrawals

### Nice to have

- admin alerts for failed withdrawals
- hot wallet minimum reserve checks
- temporary user lockouts after repeated invalid commands

## Security Notes

- master wallet seed compromise means full custodial compromise
- do not log private keys, seeds, or decrypted sensitive payloads
- keep signing isolated behind a wallet service boundary
- validate all SIKKA addresses before storing or sending
- prefer explicit statuses over implicit retries

## Suggested Implementation Order

### Phase 1: Refactor current bot internals

- extract wallet and transaction code from the current Discord-specific flow
- keep SIKKA send logic reusable from other handlers
- keep SQLite initialization modular

### Phase 2: Add ledger and idempotency tables

- add user, balance, processed-event, tip, withdrawal, and DM outbox tables
- add helper methods for atomic balance updates

### Phase 3: Add Nostr relay client

- connect to a small relay allowlist
- subscribe to relevant event kinds
- validate and dedupe events

### Phase 4: Implement public tip commands

- parse strict tip syntax
- resolve recipient pubkey
- apply ledger transfer
- queue recipient DM

### Phase 5: Implement DM command handler

- `help`
- `balance`
- `deposit`
- `withdraw`
- `withdraw all`
- `address set`

### Phase 6: Wire withdrawals to SIKKA send path

- reuse existing transaction builder/signing/submission logic
- store `txid` and final status

### Phase 7: Harden operations

- add metrics and logs
- add retry policy for outbound DMs
- add tests for duplicate relay delivery and restart safety

## Open Decisions

These must be answered before coding starts:

1. Will v1 use internal balances only, or immediate on-chain payout for some cases?
2. How do users fund balances in v1: admin top-up, treasury credit, or deposit addresses?
3. Which relays are allowed in v1?
4. Will public tips require an explicit recipient mention or only reply context?
5. Should withdrawals require a stored address, or allow one-off destination addresses?

## Recommended v1 Answer Set

- use internal balances
- send on-chain only for withdrawals
- start with a relay allowlist
- use strict command syntax
- use NIP-17 DMs
- keep durable processed event records forever or long-term

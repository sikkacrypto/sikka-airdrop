Sikka Airdrop Bot
=================

A Discord bot that handles Sikka cryptocurrency airdrops.

This repository now also includes a separate Nostr worker process:

  ./nostr-airdrop

The Nostr worker keeps its own SQLite ledger and uses NSEC as both:

  - the bot's Nostr identity
  - the deterministic root seed source for custodial SIKKA wallets

Per-user SIKKA wallets are derived from the NSEC seed material plus the user's
Nostr public key. The implementation hashes that concatenated material to a
32-byte ML-DSA seed before deriving the on-chain wallet, because the SIKKA
wallet format requires a fixed-size seed.

Required Environment Variables
-------------------------------
  sikkanode       - Sikka node URL, or a comma-separated list of node URLs.
                    The bot probes /v1/status and picks the valid node with the
                    highest reported DAG size.
  privatekey      - Hex-encoded private key used to sign transactions
  discordtoken    - Discord bot token
  discordguild    - Discord server (guild) ID to restrict the bot to
  discordchannel  - Discord channel ID to restrict the bot to

Nostr worker variables:
  nostrrelays     - Comma-separated relay allowlist.
  nsec            - Bot NSEC; also used as the deterministic wallet seed root.
  dbpath          - Optional SQLite path for the Nostr worker. Defaults to
                    /data/nostr.db.
  mintip          - Optional minimum tip amount.
  maxtip          - Optional maximum tip amount.

  To find these IDs: enable Developer Mode in Discord (Settings > Advanced),
  then right-click the server name or channel name and select "Copy ID".
  Example URL: discord.com/channels/{discordguild}/{discordchannel}

Node API Compatibility
----------------------
  This bot expects the current node HTTP API and uses these routes:

  GET  /v1/address/{address}
  GET  /v1/status (uses the tips field from the status response)
  POST /v1/tx/pow-quote
  POST /v1/tx/submit

  The address response should include: address, balance, utxo_count, utxos.
  The PoW quote response should include: required_bits.

Build
-----
  docker build -t airdrop .

Run
---
  docker run -d \
    --name airdrop \
    -e sikkanode=http://node1:8080,http://node2:8080,http://node3:8080 \
    -e privatekey=your-hex-private-key \
    -e discordtoken=your-discord-bot-token \
    -e discordguild=1508845537737048206 \
    -e discordchannel=1508860165653401762 \
    -v airdrop-data:/data \
    airdrop

The SQLite database is persisted in a Docker volume mounted at /data.

Run Nostr Worker
----------------
  docker run -d \
    --name nostr-airdrop \
    -e sikkanode=http://node1:8080,http://node2:8080 \
    -e nostrrelays=wss://relay1.example,wss://relay2.example \
    -e nsec=your-nsec \
    -v airdrop-data:/data \
    airdrop ./nostr-airdrop

Nostr Worker Commands
---------------------
  Public notes:
    sikka tip <amount> @npub...
    sikka tip @npub...             (defaults to 1% of sender available balance)
    sikka tip                      (as a reply, defaults to 1% of sender available balance)
    sikka tip <amount>            (when sent as a reply, tips the parent post author)

  Direct messages:
    help
    balance
    deposit
    address set <sikka-address>
    withdraw all <address>
    withdraw <amount> <address>

The Nostr worker currently uses NIP-04 encrypted direct messages for maximum
library compatibility.

Reply-Based Tips
----------------
If a public note contains only:

  sikka tip <amount>

or only:

  sikka tip

and that note is posted as a reply to another Nostr event, the worker resolves
the recipient from the parent event author. If no amount is provided, the
worker uses 1% of the sender's available internal balance. If the parent event
cannot be resolved from reply tags, the command must include an explicit npub.

Successful public tips also trigger a public in-thread receipt reply from the
bot. Public tips are sent on-chain to the recipient's deterministic deposit
wallet, and the receipt includes the txid plus a sikka.click transaction link.

Nostr Intake Safety Rules
------------------------
Incoming Nostr events are guarded in two ways:

  - every incoming event ID is kept in memory for 10 minutes to suppress
    duplicate relay deliveries inside the running worker process
  - events older than 2 minutes are ignored before command processing

The in-memory recent-event window is a short-window duplicate barrier. The
permanent processed-events table is still used as the final idempotency
boundary for any action that changes balances or creates withdrawals.

Stop / Remove
-------------
  docker stop airdrop
  docker rm airdrop

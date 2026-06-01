Sikka Airdrop Bot
=================

A Discord bot that handles Sikka cryptocurrency airdrops.

Required Environment Variables
-------------------------------
  sikkanode       - URL of the Sikka node (e.g. http://localhost:8080)
  privatekey      - Hex-encoded private key used to sign transactions
  discordtoken    - Discord bot token
  discordguild    - Discord server (guild) ID to restrict the bot to
  discordchannel  - Discord channel ID to restrict the bot to

  To find these IDs: enable Developer Mode in Discord (Settings > Advanced),
  then right-click the server name or channel name and select "Copy ID".
  Example URL: discord.com/channels/{discordguild}/{discordchannel}

Build
-----
  docker build -t airdrop .

Run
---
  docker run -d \
    --name airdrop \
    -e sikkanode=http://your-node-url:8080 \
    -e privatekey=your-hex-private-key \
    -e discordtoken=your-discord-bot-token \
    -e discordguild=1508845537737048206 \
    -e discordchannel=1508860165653401762 \
    -v airdrop-data:/data \
    airdrop

The SQLite database is persisted in a Docker volume mounted at /data.

Stop / Remove
-------------
  docker stop airdrop
  docker rm airdrop

# mcpe-udp-dump

Rust UDP proxy for Minecraft PE, useful for debug and packet dumps around MCPE 1.1.x / protocol 113.

## Features

- UDP proxy between client and upstream server
- logs both directions
- optional hex dump for every datagram
- basic RakNet frame-set parsing
- detects and inflates MCPE Batch packets (`0xFE`)
- prints inner MCPE packet ids and names

## Usage

```bash
cargo run --release -- \
  --bind 0.0.0.0:19133 \
  --upstream 127.0.0.1:19132 \
  --hex
```

Then connect the MCPE client to `127.0.0.1:19133` instead of the real server.

## Example output

```text
[1712345678.123] [Client->Server] 67 bytes from 192.168.0.10:50123 | udp_id=0x84 (FrameSet)
  [raknet] frame_set id=0x84 seq=150
    [frame #0] off=4 len=31 reliability=reliable_ordered, reliable_index=300, order_or_seq_index=120, channel=0 mcpe_id=0x01 (Login)
```

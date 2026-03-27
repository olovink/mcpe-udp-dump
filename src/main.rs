use anyhow::{Context, Result};
use clap::Parser;
use flate2::read::ZlibDecoder;
use std::fmt::Write as _;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const DEFAULT_BIND_ADDR: &str = "0.0.0.0:19133";
const EPHEMERAL_BIND_ADDR: &str = "0.0.0.0:0";
const DEFAULT_HEX_ENABLED: bool = false;
const DEFAULT_PARSE_RAKNET: bool = true;
const DEFAULT_INFLATE_BATCH: bool = true;
const DEFAULT_MAX_DUMP: usize = 256;
const UDP_BUFFER_SIZE: usize = 65_535;
const EMPTY_BYTE: u8 = 0;
const FRAME_SET_HEADER_LEN: usize = 4;
const FRAME_FLAGS_LEN: usize = 1;
const FRAME_BIT_LENGTH_LEN: usize = 2;
const FRAME_INDEX_LEN: usize = 3;
const FRAME_ORDER_INFO_LEN: usize = 4;
const SPLIT_INFO_LEN: usize = 10;
const SPLIT_COUNT_LEN: usize = 4;
const SPLIT_ID_LEN: usize = 2;
const SPLIT_INDEX_LEN: usize = 4;
const RELIABILITY_SHIFT: u8 = 5;
const RELIABILITY_MASK: u8 = 0x07;
const SPLIT_FLAG: u8 = 0x10;
const BYTE_BITS: usize = 8;
const U24_BYTE_1_SHIFT: u32 = 8;
const U24_BYTE_2_SHIFT: u32 = 16;
const VARINT_DATA_MASK: u8 = 0x7f;
const VARINT_CONTINUATION_BIT: u8 = 0x80;
const VARINT_SHIFT_STEP: u32 = 7;
const VARINT_MAX_SHIFT: u32 = 28;
const HEX_DUMP_ROW_BYTES: usize = 16;
const HEX_DUMP_INDENT: usize = 6;
const BATCH_HEX_DUMP_INDENT: usize = 10;
const ASCII_SPACE: u8 = b' ';
const NON_PRINTABLE_REPLACEMENT: char = '.';
const MILLIS_WIDTH: usize = 3;
const RAKNET_FRAME_SET_MIN_ID: u8 = 0x80;
const RAKNET_FRAME_SET_MAX_ID: u8 = 0x8d;
const MCPE_BATCH_PACKET_ID: u8 = 0xfe;
const MIN_FRAME_PAYLOAD_LEN_FOR_BATCH: usize = 1;
const RAKNET_UNCONNECTED_PING_ID: u8 = 0x01;
const RAKNET_UNCONNECTED_PONG_ID: u8 = 0x1c;
const RAKNET_OPEN_CONNECTION_REQUEST_1_ID: u8 = 0x05;
const RAKNET_OPEN_CONNECTION_REPLY_1_ID: u8 = 0x06;
const RAKNET_OPEN_CONNECTION_REQUEST_2_ID: u8 = 0x07;
const RAKNET_OPEN_CONNECTION_REPLY_2_ID: u8 = 0x08;
const RAKNET_CONNECTION_REQUEST_ID: u8 = 0x09;
const RAKNET_CONNECTION_REQUEST_ACCEPTED_ID: u8 = 0x10;
const RAKNET_CONNECTED_PING_ID: u8 = 0x13;
const RAKNET_CONNECTED_PONG_ID: u8 = 0x15;
const RELIABILITY_UNRELIABLE_SEQUENCED: u8 = 1;
const RELIABILITY_RELIABLE: u8 = 2;
const RELIABILITY_RELIABLE_ORDERED: u8 = 3;
const RELIABILITY_RELIABLE_SEQUENCED: u8 = 4;
const RELIABILITY_UNRELIABLE_WITH_ACK_RECEIPT: u8 = 5;
const RELIABILITY_RELIABLE_WITH_ACK_RECEIPT: u8 = 6;
const RELIABILITY_RELIABLE_ORDERED_WITH_ACK_RECEIPT: u8 = 7;
const MCPE_LOGIN_ID: u8 = 0x01;
const MCPE_PLAY_STATUS_ID: u8 = 0x02;
const MCPE_SERVER_TO_CLIENT_HANDSHAKE_ID: u8 = 0x03;
const MCPE_CLIENT_TO_SERVER_HANDSHAKE_ID: u8 = 0x04;
const MCPE_DISCONNECT_ID: u8 = 0x05;
const MCPE_RESOURCE_PACKS_INFO_ID: u8 = 0x06;
const MCPE_RESOURCE_PACK_STACK_ID: u8 = 0x07;
const MCPE_RESOURCE_PACK_CLIENT_RESPONSE_ID: u8 = 0x08;
const MCPE_TEXT_ID: u8 = 0x09;
const MCPE_SET_TIME_ID: u8 = 0x0a;
const MCPE_START_GAME_ID: u8 = 0x0b;
const MCPE_ADD_PLAYER_ID: u8 = 0x0c;
const MCPE_ADD_ENTITY_ID: u8 = 0x0d;
const MCPE_REMOVE_ENTITY_ID: u8 = 0x0e;
const MCPE_ADD_ITEM_ENTITY_ID: u8 = 0x0f;
const MCPE_TAKE_ITEM_ENTITY_ID: u8 = 0x10;
const MCPE_MOVE_ENTITY_ID: u8 = 0x11;
const MCPE_MOVE_PLAYER_ID: u8 = 0x12;
const MCPE_RIDER_JUMP_ID: u8 = 0x13;
const MCPE_UPDATE_BLOCK_ID: u8 = 0x14;
const MCPE_ADD_PAINTING_ID: u8 = 0x15;
const MCPE_EXPLODE_ID: u8 = 0x16;
const MCPE_LEVEL_SOUND_EVENT_ID: u8 = 0x17;
const MCPE_LEVEL_EVENT_ID: u8 = 0x18;
const MCPE_BLOCK_EVENT_ID: u8 = 0x19;
const MCPE_ENTITY_EVENT_ID: u8 = 0x1a;
const MCPE_MOB_EFFECT_ID: u8 = 0x1b;
const MCPE_UPDATE_ATTRIBUTES_ID: u8 = 0x1c;
const MCPE_INVENTORY_TRANSACTION_ID: u8 = 0x1d;
const MCPE_MOB_EQUIPMENT_ID: u8 = 0x1e;
const MCPE_MOB_ARMOR_EQUIPMENT_ID: u8 = 0x1f;
const MCPE_INTERACT_ID: u8 = 0x20;
const MCPE_BLOCK_PICK_REQUEST_ID: u8 = 0x21;
const MCPE_ENTITY_PICK_REQUEST_ID: u8 = 0x22;
const MCPE_PLAYER_ACTION_ID: u8 = 0x23;
const MCPE_HURT_ARMOR_ID: u8 = 0x24;
const MCPE_SET_ENTITY_DATA_ID: u8 = 0x25;
const MCPE_SET_ENTITY_MOTION_ID: u8 = 0x26;
const MCPE_SET_ENTITY_LINK_ID: u8 = 0x27;
const MCPE_SET_HEALTH_ID: u8 = 0x28;
const MCPE_SET_SPAWN_POSITION_ID: u8 = 0x29;
const MCPE_ANIMATE_ID: u8 = 0x2a;
const MCPE_RESPAWN_ID: u8 = 0x2b;
const MCPE_CONTAINER_OPEN_ID: u8 = 0x2c;
const MCPE_CONTAINER_CLOSE_ID: u8 = 0x2d;
const MCPE_PLAYER_HOTBAR_ID: u8 = 0x2e;
const MCPE_INVENTORY_CONTENT_ID: u8 = 0x2f;
const MCPE_INVENTORY_SLOT_ID: u8 = 0x30;
const MCPE_CONTAINER_SET_DATA_ID: u8 = 0x31;
const MCPE_CRAFTING_DATA_ID: u8 = 0x32;
const MCPE_CRAFTING_EVENT_ID: u8 = 0x33;
const MCPE_GUI_DATA_PICK_ITEM_ID: u8 = 0x34;
const MCPE_ADVENTURE_SETTINGS_ID: u8 = 0x35;
const MCPE_BLOCK_ENTITY_DATA_ID: u8 = 0x36;
const MCPE_PLAYER_INPUT_ID: u8 = 0x37;
const MCPE_LEVEL_CHUNK_ID: u8 = 0x38;
const MCPE_SET_COMMANDS_ENABLED_ID: u8 = 0x39;
const MCPE_SET_DIFFICULTY_ID: u8 = 0x3a;
const MCPE_CHANGE_DIMENSION_ID: u8 = 0x3b;
const MCPE_SET_PLAYER_GAME_TYPE_ID: u8 = 0x3c;
const MCPE_PLAYER_LIST_ID: u8 = 0x3d;
const MCPE_SIMPLE_EVENT_ID: u8 = 0x3e;
const MCPE_TELEMETRY_EVENT_ID: u8 = 0x3f;
const MCPE_SPAWN_EXPERIENCE_ORB_ID: u8 = 0x40;
const MCPE_CLIENTBOUND_MAP_ITEM_DATA_ID: u8 = 0x41;
const MCPE_MAP_INFO_REQUEST_ID: u8 = 0x42;
const MCPE_REQUEST_CHUNK_RADIUS_ID: u8 = 0x43;
const MCPE_CHUNK_RADIUS_UPDATED_ID: u8 = 0x44;
const MCPE_ITEM_FRAME_DROP_ITEM_ID: u8 = 0x45;
const MCPE_GAME_RULES_CHANGED_ID: u8 = 0x46;
const MCPE_CAMERA_ID: u8 = 0x47;
const MCPE_BOSS_EVENT_ID: u8 = 0x48;
const MCPE_SHOW_CREDITS_ID: u8 = 0x49;
const MCPE_AVAILABLE_COMMANDS_ID: u8 = 0x4a;
const MCPE_COMMAND_REQUEST_ID: u8 = 0x4b;
const MCPE_COMMAND_BLOCK_UPDATE_ID: u8 = 0x4c;
const MCPE_COMMAND_OUTPUT_ID: u8 = 0x4d;
const MCPE_UPDATE_TRADE_ID: u8 = 0x4e;
const MCPE_UPDATE_EQUIPMENT_ID: u8 = 0x4f;
const MCPE_RESOURCE_PACK_DATA_INFO_ID: u8 = 0x50;
const MCPE_RESOURCE_PACK_CHUNK_DATA_ID: u8 = 0x51;
const MCPE_RESOURCE_PACK_CHUNK_REQUEST_ID: u8 = 0x52;
const MCPE_TRANSFER_ID: u8 = 0x53;
const MCPE_PLAY_SOUND_ID: u8 = 0x54;
const MCPE_STOP_SOUND_ID: u8 = 0x55;
const MCPE_SET_TITLE_ID: u8 = 0x56;
const MCPE_ADD_BEHAVIOR_TREE_ID: u8 = 0x57;
const MCPE_STRUCTURE_BLOCK_UPDATE_ID: u8 = 0x58;
const MCPE_SHOW_STORE_OFFER_ID: u8 = 0x59;
const MCPE_PURCHASE_RECEIPT_ID: u8 = 0x5a;

#[derive(Parser, Debug, Clone)]
#[command(name = "mcpe-dump")]
#[command(about = "Debug UDP proxy for Minecraft PE")]
struct Args {
    #[arg(long, default_value = DEFAULT_BIND_ADDR)]
    bind: String,

    #[arg(long)]
    upstream: String,

    #[arg(long, default_value_t = DEFAULT_HEX_ENABLED)]
    hex: bool,

    #[arg(long, default_value_t = DEFAULT_PARSE_RAKNET)]
    parse_raknet: bool,

    #[arg(long, default_value_t = DEFAULT_INFLATE_BATCH)]
    inflate_batch: bool,

    #[arg(long, default_value_t = DEFAULT_MAX_DUMP)]
    max_dump: usize,
}

#[derive(Clone, Copy, Debug)]
enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    fn label(self) -> &'static str {
        match self {
            Direction::ClientToServer => "Client->Server",
            Direction::ServerToClient => "Server->Client",
        }
    }
}

#[derive(Debug, Default)]
struct SessionState {
    client_addr: Option<SocketAddr>,
    last_seen: Option<Instant>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let bind_addr: SocketAddr = args.bind.parse().context("invalid --bind")?;
    let upstream_addr: SocketAddr = args.upstream.parse().context("invalid --upstream")?;

    let listener = Arc::new(UdpSocket::bind(bind_addr).await.with_context(|| format!("bind {}", bind_addr))?);
    let upstream = Arc::new(UdpSocket::bind(EPHEMERAL_BIND_ADDR).await.context("bind ephemeral upstream socket")?);
    upstream.connect(upstream_addr).await.with_context(|| format!("connect {}", upstream_addr))?;

    println!(
        "listening on {}, forwarding to {}, hex={}, parse_raknet={}, inflate_batch={}",
        bind_addr, upstream_addr, args.hex, args.parse_raknet, args.inflate_batch
    );

    let state = Arc::new(Mutex::new(SessionState::default()));

    let client_task = {
        let listener = listener.clone();
        let upstream = upstream.clone();
        let args = args.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let mut buf = vec![EMPTY_BYTE; UDP_BUFFER_SIZE];
            loop {
                let (len, from) = listener.recv_from(&mut buf).await.context("recv_from client")?;
                {
                    let mut guard = state.lock().await;
                    match guard.client_addr {
                        Some(prev) if prev != from => {
                            eprintln!("[warn] switching client {} -> {}", prev, from);
                            guard.client_addr = Some(from);
                        }
                        None => {
                            println!("[info] client connected: {}", from);
                            guard.client_addr = Some(from);
                        }
                        _ => {}
                    }
                    guard.last_seen = Some(Instant::now());
                }

                let payload = &buf[..len];
                dump_datagram(Direction::ClientToServer, from, payload, &args);
                upstream.send(payload).await.context("forward client -> upstream")?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        })
    };

    let server_task = {
        let listener = listener.clone();
        let upstream = upstream.clone();
        let args = args.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let mut buf = vec![EMPTY_BYTE; UDP_BUFFER_SIZE];
            loop {
                let len = upstream.recv(&mut buf).await.context("recv from upstream")?;
                let client = {
                    let mut guard = state.lock().await;
                    guard.last_seen = Some(Instant::now());
                    guard.client_addr
                };

                let payload = &buf[..len];
                dump_datagram(Direction::ServerToClient, upstream_addr, payload, &args);

                if let Some(client_addr) = client {
                    listener
                        .send_to(payload, client_addr)
                        .await
                        .context("forward upstream -> client")?;
                } else {
                    eprintln!("[warn] dropping server packet: no client seen yet");
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        })
    };

    tokio::select! {
        result = client_task => result.context("client task join")??,
        result = server_task => result.context("server task join")??,
    }

    Ok(())
}

fn dump_datagram(direction: Direction, peer: SocketAddr, payload: &[u8], args: &Args) {
    let now = chrono_like_timestamp();
    let first = payload.first().copied().unwrap_or(EMPTY_BYTE);
    println!(
        "\n[{now}] [{}] {} bytes from {} | udp_id=0x{first:02X} ({})",
        direction.label(),
        payload.len(),
        peer,
        raknet_datagram_name(first)
    );

    if args.hex {
        println!("{}", hex_dump(payload, args.max_dump));
    }

    if args.parse_raknet {
        if let Err(err) = parse_raknet_datagram(direction, payload, args) {
            eprintln!("  [raknet parse error] {err:#}");
        }
    }
}

fn parse_raknet_datagram(direction: Direction, payload: &[u8], args: &Args) -> Result<()> {
    if payload.is_empty() {
        return Ok(());
    }

    let id = payload[0];
    match id {
        // 0x80 - 0x8d (RakNet)
        RAKNET_FRAME_SET_MIN_ID..=RAKNET_FRAME_SET_MAX_ID => parse_frame_set(direction, payload, args),
        _ => {
            println!("  [raknet] control packet: {}", raknet_datagram_name(id));
            Ok(())
        }
    }
}

fn parse_frame_set(direction: Direction, payload: &[u8], args: &Args) -> Result<()> {
    if payload.len() < FRAME_SET_HEADER_LEN {
        anyhow::bail!("frame set too short");
    }

    let packet_id = payload[0];
    let seq = u24_le(&payload[1..FRAME_SET_HEADER_LEN]);
    println!("  [raknet] frame_set id=0x{packet_id:02X} seq={seq}");

    let mut offset = FRAME_SET_HEADER_LEN;
    let mut index = 0usize;
    while offset < payload.len() {
        let start = offset;
        let flags = *payload.get(offset).context("missing frame flags")?;
        offset += FRAME_FLAGS_LEN;

        let bit_len = u16::from_be_bytes([
            *payload.get(offset).context("missing frame bit length hi")?,
            *payload.get(offset + FRAME_FLAGS_LEN).context("missing frame bit length lo")?,
        ]);
        offset += FRAME_BIT_LENGTH_LEN;
        let byte_len = ((bit_len as usize) + (BYTE_BITS - 1)) / BYTE_BITS;

        let reliability = (flags >> RELIABILITY_SHIFT) & RELIABILITY_MASK;
        let has_split = (flags & SPLIT_FLAG) != 0;

        let reliable_index = if matches!(
            reliability,
            RELIABILITY_RELIABLE
                | RELIABILITY_RELIABLE_ORDERED
                | RELIABILITY_RELIABLE_SEQUENCED
                | RELIABILITY_RELIABLE_WITH_ACK_RECEIPT
                | RELIABILITY_RELIABLE_ORDERED_WITH_ACK_RECEIPT
        ) {
            let v = u24_le(payload.get(offset..offset + FRAME_INDEX_LEN).context("missing reliable index")?);
            offset += FRAME_INDEX_LEN;
            Some(v)
        } else {
            None
        };

        let sequencing_index = if matches!(reliability, RELIABILITY_UNRELIABLE_SEQUENCED | RELIABILITY_RELIABLE_SEQUENCED) {
            let index = u24_le(payload.get(offset..offset + FRAME_INDEX_LEN).context("missing sequencing index")?);
            let order_channel = *payload.get(offset + FRAME_INDEX_LEN).context("missing order channel")?;
            offset += FRAME_ORDER_INFO_LEN;
            Some((index, order_channel))
        } else if matches!(reliability, RELIABILITY_RELIABLE_ORDERED | RELIABILITY_RELIABLE_ORDERED_WITH_ACK_RECEIPT) {
            let index = u24_le(payload.get(offset..offset + FRAME_INDEX_LEN).context("missing ordered index")?);
            let order_channel = *payload.get(offset + FRAME_INDEX_LEN).context("missing ordered channel")?;
            offset += FRAME_ORDER_INFO_LEN;
            Some((index, order_channel))
        } else {
            None
        };

        let split = if has_split {
            let count = u32::from_be_bytes(payload.get(offset..offset + SPLIT_COUNT_LEN).context("missing split count")?.try_into()?);
            let split_id = u16::from_be_bytes(
                payload
                    .get(offset + SPLIT_COUNT_LEN..offset + SPLIT_COUNT_LEN + SPLIT_ID_LEN)
                    .context("missing split id")?
                    .try_into()?,
            );
            let split_index = u32::from_be_bytes(
                payload
                    .get(
                        offset + SPLIT_COUNT_LEN + SPLIT_ID_LEN
                            ..offset + SPLIT_COUNT_LEN + SPLIT_ID_LEN + SPLIT_INDEX_LEN,
                    )
                    .context("missing split index")?
                    .try_into()?,
            );
            offset += SPLIT_INFO_LEN;
            Some((count, split_id, split_index))
        } else {
            None
        };

        let frame = payload.get(offset..offset + byte_len).context("frame payload out of bounds")?;
        offset += byte_len;

        let mcpe_id = frame.first().copied().unwrap_or(EMPTY_BYTE);
        println!(
            "    [frame #{index}] off={} len={} reliability={}{}{}{} mcpe_id=0x{mcpe_id:02X} ({})",
            start,
            byte_len,
            reliability_name(reliability),
            reliable_index.map(|v| format!(", reliable_index={v}")).unwrap_or_default(),
            sequencing_index.map(|(v, ch)| format!(", order_or_seq_index={v}, channel={ch}")).unwrap_or_default(),
            split.map(|(count, split_id, split_index)| format!(", split={split_index}/{count} split_id={split_id}")).unwrap_or_default(),
            mcpe_packet_name(mcpe_id)
        );

        if args.hex {
            println!("{}", indent(&hex_dump(frame, args.max_dump), HEX_DUMP_INDENT));
        }

        if args.inflate_batch && mcpe_id == MCPE_BATCH_PACKET_ID && frame.len() > MIN_FRAME_PAYLOAD_LEN_FOR_BATCH {
            match inflate_batch_payload(&frame[MIN_FRAME_PAYLOAD_LEN_FOR_BATCH..]) {
                Ok(inflated) => {
                    println!(
                        "      [batch] inflated {} -> {} bytes",
                        frame.len() - MIN_FRAME_PAYLOAD_LEN_FOR_BATCH,
                        inflated.len()
                    );
                    for (i, pkt) in split_mcpe_batch(&inflated).iter().enumerate() {
                        let pid = pkt.first().copied().unwrap_or(EMPTY_BYTE);
                        println!(
                            "        [batch pkt #{i}] id=0x{pid:02X} ({}) len={}",
                            mcpe_packet_name(pid),
                            pkt.len()
                        );
                        if args.hex {
                            println!("{}", indent(&hex_dump(pkt, args.max_dump), BATCH_HEX_DUMP_INDENT));
                        }
                    }
                }
                Err(err) => {
                    eprintln!("      [batch inflate error] {err:#}");
                }
            }
        }

        index += 1;
    }

    match direction {
        Direction::ClientToServer => {}
        Direction::ServerToClient => {}
    }

    Ok(())
}

fn inflate_batch_payload(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).context("zlib inflate failed")?;
    Ok(out)
}

fn split_mcpe_batch(mut data: &[u8]) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    while !data.is_empty() {
        match read_unsigned_varint(data) {
            Some((len, used)) => {
                data = &data[used..];
                if len as usize > data.len() {
                    packets.push(data.to_vec());
                    break;
                }
                let (pkt, rest) = data.split_at(len as usize);
                packets.push(pkt.to_vec());
                data = rest;
            }
            None => {
                packets.push(data.to_vec());
                break;
            }
        }
    }
    packets
}

fn read_unsigned_varint(data: &[u8]) -> Option<(u32, usize)> {
    let mut value = 0u32;
    let mut shift = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        value |= ((byte & VARINT_DATA_MASK) as u32) << shift;
        if (byte & VARINT_CONTINUATION_BIT) == 0 {
            return Some((value, i + FRAME_FLAGS_LEN));
        }
        shift += VARINT_SHIFT_STEP;
        if shift > VARINT_MAX_SHIFT {
            return None;
        }
    }
    None
}

fn u24_le(bytes: &[u8]) -> u32 {
    (bytes[0] as u32)
        | ((bytes[1] as u32) << U24_BYTE_1_SHIFT)
        | ((bytes[2] as u32) << U24_BYTE_2_SHIFT)
}

fn hex_dump(data: &[u8], max: usize) -> String {
    let slice = if max == 0 || data.len() <= max { data } else { &data[..max] };
    let mut out = String::new();
    for (row, chunk) in slice.chunks(HEX_DUMP_ROW_BYTES).enumerate() {
        let offset = row * HEX_DUMP_ROW_BYTES;
        let _ = write!(&mut out, "{:04x}: ", offset);
        for byte in chunk {
            let _ = write!(&mut out, "{:02x} ", byte);
        }
        for _ in chunk.len()..HEX_DUMP_ROW_BYTES {
            out.push_str("   ");
        }
        out.push_str(" | ");
        for &byte in chunk {
            let ch = if byte.is_ascii_graphic() || byte == ASCII_SPACE {
                byte as char
            } else {
                NON_PRINTABLE_REPLACEMENT
            };
            out.push(ch);
        }
        out.push('\n');
    }
    if slice.len() < data.len() {
        let _ = writeln!(&mut out, "... truncated {} bytes", data.len() - slice.len());
    }
    out
}

fn indent(text: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    text.lines()
        .map(|line| format!("{pad}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

    fn chrono_like_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    format!("{}. {:0width$}", dur.as_secs(), dur.subsec_millis(), width = MILLIS_WIDTH).replace(" ", "")
}

fn raknet_datagram_name(id: u8) -> &'static str {
    match id {
        RAKNET_UNCONNECTED_PING_ID => "UnconnectedPing",
        RAKNET_UNCONNECTED_PONG_ID => "UnconnectedPong",
        RAKNET_OPEN_CONNECTION_REQUEST_1_ID => "OpenConnectionRequest1",
        RAKNET_OPEN_CONNECTION_REPLY_1_ID => "OpenConnectionReply1",
        RAKNET_OPEN_CONNECTION_REQUEST_2_ID => "OpenConnectionRequest2",
        RAKNET_OPEN_CONNECTION_REPLY_2_ID => "OpenConnectionReply2",
        RAKNET_CONNECTION_REQUEST_ID => "ConnectionRequest",
        RAKNET_CONNECTION_REQUEST_ACCEPTED_ID => "ConnectionRequestAccepted/NewIncomingConnection",
        RAKNET_CONNECTED_PING_ID => "ConnectedPing",
        RAKNET_CONNECTED_PONG_ID => "ConnectedPong",
        RAKNET_FRAME_SET_MIN_ID..=RAKNET_FRAME_SET_MAX_ID => "FrameSet",
        _ => "Unknown/Other",
    }
}

fn reliability_name(v: u8) -> &'static str {
    match v {
        0 => "unreliable",
        RELIABILITY_UNRELIABLE_SEQUENCED => "unreliable_sequenced",
        RELIABILITY_RELIABLE => "reliable",
        RELIABILITY_RELIABLE_ORDERED => "reliable_ordered",
        RELIABILITY_RELIABLE_SEQUENCED => "reliable_sequenced",
        RELIABILITY_UNRELIABLE_WITH_ACK_RECEIPT => "unreliable_with_ack_receipt",
        RELIABILITY_RELIABLE_WITH_ACK_RECEIPT => "reliable_with_ack_receipt",
        RELIABILITY_RELIABLE_ORDERED_WITH_ACK_RECEIPT => "reliable_ordered_with_ack_receipt",
        _ => "unknown",
    }
}

fn mcpe_packet_name(id: u8) -> &'static str {
    match id {
        MCPE_LOGIN_ID => "Login",
        MCPE_PLAY_STATUS_ID => "PlayStatus",
        MCPE_SERVER_TO_CLIENT_HANDSHAKE_ID => "ServerToClientHandshake",
        MCPE_CLIENT_TO_SERVER_HANDSHAKE_ID => "ClientToServerHandshake",
        MCPE_DISCONNECT_ID => "Disconnect",
        MCPE_RESOURCE_PACKS_INFO_ID => "ResourcePacksInfo",
        MCPE_RESOURCE_PACK_STACK_ID => "ResourcePackStack",
        MCPE_RESOURCE_PACK_CLIENT_RESPONSE_ID => "ResourcePackClientResponse",
        MCPE_TEXT_ID => "Text",
        MCPE_SET_TIME_ID => "SetTime",
        MCPE_START_GAME_ID => "StartGame",
        MCPE_ADD_PLAYER_ID => "AddPlayer",
        MCPE_ADD_ENTITY_ID => "AddEntity",
        MCPE_REMOVE_ENTITY_ID => "RemoveEntity",
        MCPE_ADD_ITEM_ENTITY_ID => "AddItemEntity",
        MCPE_TAKE_ITEM_ENTITY_ID => "TakeItemEntity",
        MCPE_MOVE_ENTITY_ID => "MoveEntity",
        MCPE_MOVE_PLAYER_ID => "MovePlayer",
        MCPE_RIDER_JUMP_ID => "RiderJump",
        MCPE_UPDATE_BLOCK_ID => "UpdateBlock",
        MCPE_ADD_PAINTING_ID => "AddPainting",
        MCPE_EXPLODE_ID => "Explode",
        MCPE_LEVEL_SOUND_EVENT_ID => "LevelSoundEvent",
        MCPE_LEVEL_EVENT_ID => "LevelEvent",
        MCPE_BLOCK_EVENT_ID => "BlockEvent",
        MCPE_ENTITY_EVENT_ID => "EntityEvent",
        MCPE_MOB_EFFECT_ID => "MobEffect",
        MCPE_UPDATE_ATTRIBUTES_ID => "UpdateAttributes",
        MCPE_INVENTORY_TRANSACTION_ID => "InventoryTransaction",
        MCPE_MOB_EQUIPMENT_ID => "MobEquipment",
        MCPE_MOB_ARMOR_EQUIPMENT_ID => "MobArmorEquipment",
        MCPE_INTERACT_ID => "Interact",
        MCPE_BLOCK_PICK_REQUEST_ID => "BlockPickRequest",
        MCPE_ENTITY_PICK_REQUEST_ID => "EntityPickRequest",
        MCPE_PLAYER_ACTION_ID => "PlayerAction",
        MCPE_HURT_ARMOR_ID => "HurtArmor",
        MCPE_SET_ENTITY_DATA_ID => "SetEntityData",
        MCPE_SET_ENTITY_MOTION_ID => "SetEntityMotion",
        MCPE_SET_ENTITY_LINK_ID => "SetEntityLink",
        MCPE_SET_HEALTH_ID => "SetHealth",
        MCPE_SET_SPAWN_POSITION_ID => "SetSpawnPosition",
        MCPE_ANIMATE_ID => "Animate",
        MCPE_RESPAWN_ID => "Respawn",
        MCPE_CONTAINER_OPEN_ID => "ContainerOpen",
        MCPE_CONTAINER_CLOSE_ID => "ContainerClose",
        MCPE_PLAYER_HOTBAR_ID => "PlayerHotbar",
        MCPE_INVENTORY_CONTENT_ID => "InventoryContent",
        MCPE_INVENTORY_SLOT_ID => "InventorySlot",
        MCPE_CONTAINER_SET_DATA_ID => "ContainerSetData",
        MCPE_CRAFTING_DATA_ID => "CraftingData",
        MCPE_CRAFTING_EVENT_ID => "CraftingEvent",
        MCPE_GUI_DATA_PICK_ITEM_ID => "GuiDataPickItem",
        MCPE_ADVENTURE_SETTINGS_ID => "AdventureSettings",
        MCPE_BLOCK_ENTITY_DATA_ID => "BlockEntityData",
        MCPE_PLAYER_INPUT_ID => "PlayerInput",
        MCPE_LEVEL_CHUNK_ID => "LevelChunk",
        MCPE_SET_COMMANDS_ENABLED_ID => "SetCommandsEnabled",
        MCPE_SET_DIFFICULTY_ID => "SetDifficulty",
        MCPE_CHANGE_DIMENSION_ID => "ChangeDimension",
        MCPE_SET_PLAYER_GAME_TYPE_ID => "SetPlayerGameType",
        MCPE_PLAYER_LIST_ID => "PlayerList",
        MCPE_SIMPLE_EVENT_ID => "SimpleEvent",
        MCPE_TELEMETRY_EVENT_ID => "TelemetryEvent",
        MCPE_SPAWN_EXPERIENCE_ORB_ID => "SpawnExperienceOrb",
        MCPE_CLIENTBOUND_MAP_ITEM_DATA_ID => "ClientboundMapItemData",
        MCPE_MAP_INFO_REQUEST_ID => "MapInfoRequest",
        MCPE_REQUEST_CHUNK_RADIUS_ID => "RequestChunkRadius",
        MCPE_CHUNK_RADIUS_UPDATED_ID => "ChunkRadiusUpdated",
        MCPE_ITEM_FRAME_DROP_ITEM_ID => "ItemFrameDropItem",
        MCPE_GAME_RULES_CHANGED_ID => "GameRulesChanged",
        MCPE_CAMERA_ID => "Camera",
        MCPE_BOSS_EVENT_ID => "BossEvent",
        MCPE_SHOW_CREDITS_ID => "ShowCredits",
        MCPE_AVAILABLE_COMMANDS_ID => "AvailableCommands",
        MCPE_COMMAND_REQUEST_ID => "CommandRequest",
        MCPE_COMMAND_BLOCK_UPDATE_ID => "CommandBlockUpdate",
        MCPE_COMMAND_OUTPUT_ID => "CommandOutput",
        MCPE_UPDATE_TRADE_ID => "UpdateTrade",
        MCPE_UPDATE_EQUIPMENT_ID => "UpdateEquipment",
        MCPE_RESOURCE_PACK_DATA_INFO_ID => "ResourcePackDataInfo",
        MCPE_RESOURCE_PACK_CHUNK_DATA_ID => "ResourcePackChunkData",
        MCPE_RESOURCE_PACK_CHUNK_REQUEST_ID => "ResourcePackChunkRequest",
        MCPE_TRANSFER_ID => "Transfer",
        MCPE_PLAY_SOUND_ID => "PlaySound",
        MCPE_STOP_SOUND_ID => "StopSound",
        MCPE_SET_TITLE_ID => "SetTitle",
        MCPE_ADD_BEHAVIOR_TREE_ID => "AddBehaviorTree",
        MCPE_STRUCTURE_BLOCK_UPDATE_ID => "StructureBlockUpdate",
        MCPE_SHOW_STORE_OFFER_ID => "ShowStoreOffer",
        MCPE_PURCHASE_RECEIPT_ID => "PurchaseReceipt",
        MCPE_BATCH_PACKET_ID => "Batch",
        _ => "Unknown/Unmapped",
    }
}

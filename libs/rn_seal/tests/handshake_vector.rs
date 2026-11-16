use rn_seal::{
    mac1, mac1_key, plaintext_cap, Client, DeviceKey, Error, Frame, Keys, Ring, Rng,
    ServerHandshake, FLAG_TIME_CORRECTION, KEY_LEN, MAC1_LEN, MAX_DATAGRAM, PAD_MAX, PAD_MIN,
};

/// 固定字节的随机源。测试用它让 `e` 的最高位可控。
struct FixedRng {
    byte: u8,
}

impl Rng for FixedRng {
    fn fill(&mut self, buf: &mut [u8]) -> rn_seal::Result<()> {
        for slot in buf.iter_mut() {
            *slot = self.byte;
        }
        Ok(())
    }
}

fn server_key() -> DeviceKey {
    let mut seed = [0u8; 32];
    for (index, slot) in seed.iter_mut().enumerate() {
        *slot = index as u8 + 1;
    }
    DeviceKey::from_secret_bytes(seed)
}

fn inner(body: &[u8], seq: u32) -> Vec<u8> {
    let mut rng = FixedRng { byte: 0x01 };
    Frame::new(seq, 1_700_000_000_000, body.to_vec())
        .encode(&mut rng, plaintext_cap(true))
        .expect("encode inner")
}

/// 一次完整握手，返回（请求、应答、客户端密钥、服务端密钥）。
fn handshake() -> (Vec<u8>, Vec<u8>, Keys, Keys) {
    let server = server_key();
    let request_inner = inner(b"register", 7);
    let (request, client) = Client::start(&server.public_bytes(), &request_inner).expect("start");

    let (server_inner, stage) = ServerHandshake::read(&server, &request).expect("read");
    assert_eq!(server_inner, request_inner, "服务端读到的内层帧");

    let reply_inner = inner(b"register-response", 7);
    let (reply, server_keys) = stage.respond(&reply_inner).expect("respond");

    let (client_inner, client_keys) = client.finish(&reply).expect("finish");
    assert_eq!(client_inner, reply_inner, "客户端读到的应答内层帧");
    (request, reply, client_keys, server_keys)
}

#[test]
fn handshake_hash_matches() {
    for _ in 0..3 {
        let (_, _, client, server) = handshake();
        assert_eq!(client.hash, server.hash, "两端握手哈希必须一致");
        assert_eq!(client.ack, server.ack);
    }
}

#[test]
fn push_roundtrip_rejects_replay() {
    let (_, _, client, server) = handshake();
    let mut writer = server.into_writer();
    let mut reader = client.into_reader();
    let mut rng = FixedRng { byte: 0x5A };
    let plain = inner(b"punch", 9);
    let sealed = writer.seal(&plain, &mut rng).expect("seal");
    assert_eq!(reader.open(&sealed).expect("open"), plain);
    assert!(matches!(reader.open(&sealed), Err(Error::Replay)));
}

#[test]
fn mac1_rejects_tampered_datagram() {
    let key = mac1_key(&server_key().public_bytes());
    let mut datagram = vec![0u8; 64];
    let tag = mac1(&key, &datagram);
    datagram.extend_from_slice(&tag);
    assert!(rn_seal::verify_mac1(&key, &datagram).is_ok());
    datagram[3] ^= 0x01;
    assert!(matches!(
        rn_seal::verify_mac1(&key, &datagram),
        Err(Error::Auth)
    ));
}

#[test]
fn mac1_rejects_truncated_datagram() {
    let key = mac1_key(&server_key().public_bytes());
    assert!(rn_seal::verify_mac1(&key, &[0u8; 8]).is_err());
}

#[test]
fn frame_rejects_non_zero_padding() {
    let mut rng = FixedRng { byte: 0xFF };
    let encoded = Frame::new(1, 2, b"body".to_vec())
        .encode(&mut rng, plaintext_cap(true))
        .expect("encode");
    let decoded = Frame::decode(&encoded).expect("decode");
    assert_eq!(decoded.body, b"body");
    let mut tampered = encoded.clone();
    if let Some(last) = tampered.last_mut() {
        *last = 0x7F;
    }
    assert!(Frame::decode(&tampered).is_err());
}

#[test]
fn frame_padding_is_within_bounds() {
    for byte in [0x00u8, 0x10, 0x80, 0xF0, 0xFF] {
        let mut rng = FixedRng { byte };
        let encoded = Frame::new(1, 2, b"x".to_vec())
            .encode(&mut rng, plaintext_cap(true))
            .expect("encode");
        assert!(encoded.len() >= PAD_MIN, "填充下限");
        assert!(encoded.len() <= PAD_MAX, "填充上限");
    }
    assert_eq!(FLAG_TIME_CORRECTION, 0x01);
}

#[test]
fn ring_promotes_confirmed_session() {
    let (_, _, client_a, server_a) = handshake();
    let (_, _, client_b, server_b) = handshake();
    let mut ring = Ring::new();
    ring.push(1, server_a);
    ring.push(2, server_b);
    // 未确认的会话不能用于推送：对端还没有它们的解密状态。
    assert_eq!(ring.current_seq(), None);
    assert!(ring.confirm(&client_a.ack), "旧会话确认应被接受");
    assert_eq!(ring.current_seq(), Some(1));
    assert!(ring.confirm(&client_b.ack));
    assert_eq!(ring.current_seq(), Some(2));
    assert_eq!(ring.len(), 2);
    assert!(!ring.confirm(&[0u8; 8]));
}

#[test]
fn device_key_encodes_to_base64() {
    let key = server_key();
    let text = key.secret_b64();
    let decoded = DeviceKey::from_secret_b64(&text).expect("decode");
    assert_eq!(decoded.public_bytes(), key.public_bytes());
    assert!(DeviceKey::from_secret_b64("no").is_err());
    assert_eq!(key.public_bytes().len(), KEY_LEN);
    assert_eq!(mac1(&[0u8; 32], b"x").len(), MAC1_LEN);
    assert!(plaintext_cap(true) + MAC1_LEN + KEY_LEN + 16 <= MAX_DATAGRAM);
}

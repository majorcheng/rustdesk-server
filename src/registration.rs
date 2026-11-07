use hbb_common::{base64, sodiumoxide::crypto::sign};

/// RustBot 在 `RegisterPk.old_id` 里携带的轮换载荷前缀。
///
/// `libs/hbb_common` 固定在上游 submodule，不能给 `RegisterPk` 增加字段；`old_id` 在本
/// 仓库的注册分支完全没有使用，因此用它承载固定布局的载荷。只有 RustBot peer ID 会解析，
/// stock RustDesk 客户端写入了别的内容时按“没有载荷”处理。
pub(crate) const CARRIER_PREFIX: &str = "rustnet-rotation-v1:";

const RECOVERY_PUBLIC_KEY_LEN: usize = sign::PUBLICKEYBYTES;
const SIGNATURE_LEN: usize = sign::SIGNATUREBYTES;
const PAYLOAD_LEN: usize = RECOVERY_PUBLIC_KEY_LEN + SIGNATURE_LEN * 2;
const BIND_DOMAIN: &[u8] = b"rustbot-recovery-bind-v1\n";
const ROTATE_DOMAIN: &[u8] = b"rustbot-recovery-rotate-v1\n";

/// RustBot peer ID：`rb-` 前缀加 32 位十六进制。
pub(crate) fn is_rustnet_id(id: &str) -> bool {
    match id.strip_prefix("rb-") {
        Some(hash) => hash.len() == 32 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
        None => false,
    }
}

/// 恢复公钥与两个签名。签名载荷以换行分隔，公钥放在最后，标识和 UUID 都是不含换行的定长文本。
pub(crate) struct RotationPayload {
    recovery_pk: Vec<u8>,
    binding: Vec<u8>,
    rotation: Vec<u8>,
}

impl RotationPayload {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let encoded = value.strip_prefix(CARRIER_PREFIX)?;
        let bytes = base64::decode(encoded.trim()).ok()?;
        if bytes.len() != PAYLOAD_LEN {
            return None;
        }
        Some(Self {
            recovery_pk: bytes[..RECOVERY_PUBLIC_KEY_LEN].to_vec(),
            binding: bytes[RECOVERY_PUBLIC_KEY_LEN..RECOVERY_PUBLIC_KEY_LEN + SIGNATURE_LEN]
                .to_vec(),
            rotation: bytes[RECOVERY_PUBLIC_KEY_LEN + SIGNATURE_LEN..].to_vec(),
        })
    }

    pub(crate) fn recovery_pk(&self) -> &[u8] {
        &self.recovery_pk
    }

    /// 当前主密钥对“绑定这把恢复公钥”的声明。
    pub(crate) fn binding_is_valid(&self, id: &str, uuid: &[u8], main_pk: &[u8]) -> bool {
        let mut message = Vec::with_capacity(BIND_DOMAIN.len() + id.len() + uuid.len() + 34);
        message.extend_from_slice(BIND_DOMAIN);
        message.extend_from_slice(id.as_bytes());
        message.push(b'\n');
        message.extend_from_slice(uuid);
        message.push(b'\n');
        message.extend_from_slice(&self.recovery_pk);
        verify(main_pk, &self.binding, &message)
    }

    /// 恢复密钥对“换用这把主密钥”的声明。
    pub(crate) fn rotation_is_valid(&self, id: &str, uuid: &[u8], pk: &[u8]) -> bool {
        let mut message = Vec::with_capacity(ROTATE_DOMAIN.len() + id.len() + uuid.len() + 34);
        message.extend_from_slice(ROTATE_DOMAIN);
        message.extend_from_slice(id.as_bytes());
        message.push(b'\n');
        message.extend_from_slice(uuid);
        message.push(b'\n');
        message.extend_from_slice(pk);
        verify(&self.recovery_pk, &self.rotation, &message)
    }
}

fn verify(public_key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    let Some(public_key) = sign::PublicKey::from_slice(public_key) else {
        return false;
    };
    let Ok(signature) = sign::Signature::from_bytes(signature) else {
        return false;
    };
    sign::verify_detached(&signature, message, &public_key)
}

/// 判定可用的已有身份。
///
/// `local_ip` 只来自本地注册记录：叶子租约里的地址是对方站点看到的地址，与本次连接的
/// 来源地址不可比，不能参与判定。
pub(crate) struct KnownPeer {
    pub(crate) uuid: Vec<u8>,
    pub(crate) pk: Vec<u8>,
    pub(crate) local_ip: Option<String>,
}

pub(crate) struct Incoming<'a> {
    pub(crate) id: &'a str,
    pub(crate) uuid: &'a [u8],
    pub(crate) pk: &'a [u8],
    pub(crate) ip: &'a str,
}

pub(crate) struct Verdict {
    pub(crate) accept: bool,
    pub(crate) pk_changed: bool,
    /// 本次注册可以登记（或刷新）的恢复公钥。只有被当前主密钥或恢复密钥签名的请求才会给出。
    pub(crate) enroll_recovery: Option<Vec<u8>>,
    pub(crate) reason: &'static str,
}

/// 双栈 socket 会把 IPv4 对端表示成 `::ffff:a.b.c.d`，比较来源地址前先归一化。
fn same_source_ip(left: &str, right: &str) -> bool {
    fn canonical(value: &str) -> &str {
        value.strip_prefix("::ffff:").unwrap_or(value)
    }
    canonical(left) == canonical(right)
}

fn rejected(reason: &'static str) -> Verdict {
    Verdict {
        accept: false,
        pk_changed: false,
        enroll_recovery: None,
        reason,
    }
}

/// 注册判定。已有身份优先，租约只提供集群当前的 uuid/pk 视图。
pub(crate) fn decide(
    known: Option<&KnownPeer>,
    recovery: Option<&[u8]>,
    incoming: &Incoming,
    payload: Option<&RotationPayload>,
) -> Verdict {
    let enroll = |main_pk: Option<&[u8]>| {
        payload
            .filter(|payload| match main_pk {
                Some(main_pk) => payload.binding_is_valid(incoming.id, incoming.uuid, main_pk),
                None => true,
            })
            .map(|payload| payload.recovery_pk().to_vec())
    };
    let Some(known) = known else {
        return Verdict {
            accept: true,
            pk_changed: true,
            enroll_recovery: enroll(None),
            reason: "fresh",
        };
    };
    // 老记录可能只有地址、没有 uuid，这类记录按“尚未注册”处理，与上游语义一致。
    if known.uuid.is_empty() {
        return Verdict {
            accept: true,
            pk_changed: true,
            enroll_recovery: enroll(None),
            reason: "fresh",
        };
    }
    if known.uuid != incoming.uuid {
        return rejected("uuid_mismatch");
    }
    if known.pk == incoming.pk {
        return Verdict {
            accept: true,
            pk_changed: false,
            enroll_recovery: enroll(Some(incoming.pk)),
            reason: "same_key",
        };
    }
    if let Some(payload) = payload {
        if recovery == Some(payload.recovery_pk())
            && payload.rotation_is_valid(incoming.id, incoming.uuid, incoming.pk)
        {
            return Verdict {
                accept: true,
                pk_changed: true,
                enroll_recovery: Some(payload.recovery_pk().to_vec()),
                reason: "signed_rotation",
            };
        }
    }
    // 兼容旧 Agent：来源 IP 与本地记录相同则沿用原放行规则，但不据此登记恢复公钥。
    if known
        .local_ip
        .as_deref()
        .is_some_and(|local_ip| same_source_ip(local_ip, incoming.ip))
    {
        return Verdict {
            accept: true,
            pk_changed: true,
            enroll_recovery: None,
            reason: "ip_fallback",
        };
    }
    rejected("rotation_not_authorized")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "rb-64b8716b53b1dba65ebf3f0036c15840";
    const UUID: &[u8] = b"19a5b21f-4e0c-8ef0-9082-1652f6c7748f";

    fn public(key: &sign::PublicKey) -> Vec<u8> {
        key.0.to_vec()
    }

    struct Keys {
        main: (sign::PublicKey, sign::SecretKey),
        recovery: (sign::PublicKey, sign::SecretKey),
        other: (sign::PublicKey, sign::SecretKey),
    }

    impl Keys {
        fn new() -> Self {
            Self {
                main: sign::gen_keypair(),
                recovery: sign::gen_keypair(),
                other: sign::gen_keypair(),
            }
        }

        fn payload(&self, recovery: &sign::PublicKey) -> RotationPayload {
            let mut bind = Vec::from(&BIND_DOMAIN[..]);
            bind.extend_from_slice(ID.as_bytes());
            bind.push(b'\n');
            bind.extend_from_slice(UUID);
            bind.push(b'\n');
            bind.extend_from_slice(&public(recovery));
            let mut rotate = Vec::from(&ROTATE_DOMAIN[..]);
            rotate.extend_from_slice(ID.as_bytes());
            rotate.push(b'\n');
            rotate.extend_from_slice(UUID);
            rotate.push(b'\n');
            rotate.extend_from_slice(&public(&self.main.0));
            let mut bytes = public(recovery);
            bytes.extend_from_slice(sign::sign_detached(&bind, &self.main.1).as_ref());
            bytes.extend_from_slice(sign::sign_detached(&rotate, &self.recovery.1).as_ref());
            RotationPayload::parse(&format!("{CARRIER_PREFIX}{}", base64::encode(&bytes)))
                .expect("payload should parse")
        }
    }

    #[test]
    fn rustnet_id_format() {
        assert!(is_rustnet_id(ID));
        assert!(is_rustnet_id("rb-0123456789abcdef0123456789abcdef"));
        assert!(!is_rustnet_id("rb-"));
        assert!(!is_rustnet_id("rb-0123456789abcdef0123456789abcde"));
        assert!(!is_rustnet_id("rb-0123456789abcdef0123456789abcdeg"));
        assert!(!is_rustnet_id("428172967"));
        assert!(is_rustnet_id("rb-0123456789ABCDEF0123456789ABCDEF"));
    }

    #[test]
    fn payload_parse_and_signatures() {
        let keys = Keys::new();
        let pack = keys.payload(&keys.recovery.0);
        assert_eq!(pack.recovery_pk(), public(&keys.recovery.0));
        assert!(pack.binding_is_valid(ID, UUID, &public(&keys.main.0)));
        assert!(pack.rotation_is_valid(ID, UUID, &public(&keys.main.0)));
        assert!(!pack.binding_is_valid(
            "rb-00000000000000000000000000000000",
            UUID,
            &public(&keys.main.0)
        ));
        assert!(!pack.binding_is_valid(ID, UUID, &public(&keys.other.0)));
        assert!(!pack.rotation_is_valid(ID, b"other-uuid", &public(&keys.main.0)));
        assert!(!pack.rotation_is_valid(ID, UUID, &public(&keys.other.0)));
        assert!(RotationPayload::parse("rustnet-rotation-v1:").is_none());
        assert!(RotationPayload::parse("rustnet-rotation-v1:AAAA").is_none());
        assert!(RotationPayload::parse(&format!(
            "{CARRIER_PREFIX}{}",
            base64::encode([0u8; PAYLOAD_LEN - 1])
        ))
        .is_none());
        assert!(RotationPayload::parse(&format!(
            "{CARRIER_PREFIX}{}",
            base64::encode([0u8; PAYLOAD_LEN + 1])
        ))
        .is_none());
        assert!(RotationPayload::parse("other-prefix:AAAA").is_none());
    }

    fn known(pk: &[u8], local_ip: Option<&str>) -> KnownPeer {
        KnownPeer {
            uuid: UUID.to_vec(),
            pk: pk.to_vec(),
            local_ip: local_ip.map(str::to_owned),
        }
    }

    fn incoming<'a>(pk: &'a [u8], ip: &'a str) -> Incoming<'a> {
        Incoming {
            id: ID,
            uuid: UUID,
            pk,
            ip,
        }
    }

    #[test]
    fn fresh_peer_is_accepted_and_enrolls() {
        let keys = Keys::new();
        let pack = keys.payload(&keys.recovery.0);
        let verdict = decide(
            None,
            None,
            &incoming(&public(&keys.main.0), "36.112.108.165"),
            Some(&pack),
        );
        assert!(verdict.accept);
        assert!(verdict.pk_changed);
        assert_eq!(verdict.reason, "fresh");
        assert_eq!(verdict.enroll_recovery, Some(public(&keys.recovery.0)));
    }

    #[test]
    fn empty_uuid_record_is_treated_as_fresh() {
        let keys = Keys::new();
        let mut record = known(&[], None);
        record.uuid.clear();
        let verdict = decide(
            Some(&record),
            None,
            &incoming(&public(&keys.main.0), "10.0.0.1"),
            None,
        );
        assert!(verdict.accept);
        assert_eq!(verdict.reason, "fresh");
        assert!(verdict.enroll_recovery.is_none());
    }

    #[test]
    fn uuid_mismatch_is_rejected() {
        let record = known(&[7u8; 32], Some("10.0.0.1"));
        let mut value = incoming(&[7u8; 32], "10.0.0.1");
        value.uuid = b"different";
        let verdict = decide(Some(&record), None, &value, None);
        assert!(!verdict.accept);
        assert_eq!(verdict.reason, "uuid_mismatch");
    }

    #[test]
    fn same_key_enrolls_only_with_valid_binding() {
        let keys = Keys::new();
        let record = known(&public(&keys.main.0), Some("10.0.0.1"));
        let pack = keys.payload(&keys.recovery.0);
        let verdict = decide(
            Some(&record),
            None,
            &incoming(&public(&keys.main.0), "10.0.0.1"),
            Some(&pack),
        );
        assert!(verdict.accept);
        assert!(!verdict.pk_changed);
        assert_eq!(verdict.reason, "same_key");
        assert_eq!(verdict.enroll_recovery, Some(public(&keys.recovery.0)));

        // 只换恢复公钥、绑定签名对不上时不得登记。
        let forged = RotationPayload {
            recovery_pk: public(&keys.other.0),
            binding: pack.binding.clone(),
            rotation: pack.rotation.clone(),
        };
        let verdict = decide(
            Some(&record),
            None,
            &incoming(&public(&keys.main.0), "10.0.0.1"),
            Some(&forged),
        );
        assert!(verdict.accept);
        assert!(verdict.enroll_recovery.is_none());
    }

    #[test]
    fn signed_rotation_is_accepted() {
        let keys = Keys::new();
        let record = known(&public(&keys.other.0), Some("10.0.0.1"));
        let pack = keys.payload(&keys.recovery.0);
        let verdict = decide(
            Some(&record),
            Some(&public(&keys.recovery.0)),
            &incoming(&public(&keys.main.0), "203.0.113.7"),
            Some(&pack),
        );
        assert!(verdict.accept);
        assert!(verdict.pk_changed);
        assert_eq!(verdict.reason, "signed_rotation");
        assert_eq!(verdict.enroll_recovery, Some(public(&keys.recovery.0)));
    }

    #[test]
    fn rotation_without_trusted_recovery_key_is_rejected() {
        let keys = Keys::new();
        let record = known(&public(&keys.other.0), Some("10.0.0.1"));
        let pack = keys.payload(&keys.recovery.0);
        let verdict = decide(
            Some(&record),
            None,
            &incoming(&public(&keys.main.0), "203.0.113.7"),
            Some(&pack),
        );
        assert!(!verdict.accept);
        assert_eq!(verdict.reason, "rotation_not_authorized");

        let verdict = decide(
            Some(&record),
            Some(&public(&keys.other.0)),
            &incoming(&public(&keys.main.0), "203.0.113.7"),
            Some(&pack),
        );
        assert!(!verdict.accept);
    }

    const VECTOR_ID: &str = "rb-64b8716b53b1dba65ebf3f0036c15840";
    const VECTOR_UUID: &[u8] = b"19a5b21f-4e0c-8ef0-9082-1652f6c7748f";
    const VECTOR_MAIN_PK: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
    const VECTOR_RECOVERY_PK: &str =
        "35a2f6593911a9d14d2423182ff171a8737d0a08f8df7b5678d0b12b9b31af8e";
    const VECTOR_CARRIER: &str = "rustnet-rotation-v1:NaL2WTkRqdFNJCMYL/FxqHN9Cgj433tWeNCxK5sxr448O1SnGvzdigoGYigdUdqrVGHN8gXkiWaLOHPjOij6ZZlb2L/HGTbCaoBzsGD8ji9mHuMQvPDiR8UwEUDvxCoLUN/8WjUzybj4DWWZGcrSQ/R/vK4zIoC9pG0NRWDQgFYgCT1LCDbZqH+DPRk+1yOyghAAT6Ffqh8W8webuiF0AQ==";

    fn hex_decode(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("hex text");
                u8::from_str_radix(text, 16).expect("hex byte")
            })
            .collect()
    }

    /// 与 rustnet `src/registration.rs` 的固定向量对齐：Agent 构造的 `old_id` 必须能在这里
    /// 解析并验证。任何一侧改动前缀、域分隔或字段顺序都会让该用例失败。
    #[test]
    fn agent_carrier_vector_verifies() {
        let payload = RotationPayload::parse(VECTOR_CARRIER).expect("vector parses");
        let main_pk = hex_decode(VECTOR_MAIN_PK);
        let recovery_pk = hex_decode(VECTOR_RECOVERY_PK);
        assert_eq!(payload.recovery_pk(), recovery_pk.as_slice());
        assert!(payload.binding_is_valid(VECTOR_ID, VECTOR_UUID, &main_pk));
        assert!(payload.rotation_is_valid(VECTOR_ID, VECTOR_UUID, &main_pk));

        let record = KnownPeer {
            uuid: VECTOR_UUID.to_vec(),
            pk: vec![9u8; sign::PUBLICKEYBYTES],
            local_ip: None,
        };
        let verdict = decide(
            Some(&record),
            Some(&recovery_pk),
            &Incoming {
                id: VECTOR_ID,
                uuid: VECTOR_UUID,
                pk: &main_pk,
                ip: "203.0.113.9",
            },
            Some(&payload),
        );
        assert!(verdict.accept);
        assert_eq!(verdict.reason, "signed_rotation");
    }

    #[test]
    fn ip_fallback_accepts_without_enrolling() {
        let keys = Keys::new();
        let record = known(&public(&keys.other.0), Some("10.0.0.1"));
        let pack = keys.payload(&keys.recovery.0);
        let verdict = decide(
            Some(&record),
            None,
            &incoming(&public(&keys.main.0), "10.0.0.1"),
            Some(&pack),
        );
        assert!(verdict.accept);
        assert_eq!(verdict.reason, "ip_fallback");
        assert!(verdict.enroll_recovery.is_none());

        // 租约提供不了可比来源地址，没有本地 ip 时不能走这条路径。
        let leased = known(&public(&keys.other.0), None);
        let verdict = decide(
            Some(&leased),
            None,
            &incoming(&public(&keys.main.0), "10.0.0.1"),
            None,
        );
        assert!(!verdict.accept);
    }

    #[test]
    fn ip_fallback_ignores_dual_stack_prefix() {
        let keys = Keys::new();
        let record = known(&public(&keys.other.0), Some("::ffff:36.112.108.165"));
        let verdict = decide(
            Some(&record),
            None,
            &incoming(&public(&keys.main.0), "36.112.108.165"),
            None,
        );
        assert!(verdict.accept);
        assert_eq!(verdict.reason, "ip_fallback");

        let other = decide(
            Some(&record),
            None,
            &incoming(&public(&keys.main.0), "36.112.108.166"),
            None,
        );
        assert!(!other.accept);
    }
}

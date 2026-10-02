use ciborium::Value;
use nitro_attestation::{AttestationDocument, Error};

type Map = Vec<(Value, Value)>;

fn pcrs(entries: &[(u64, Vec<u8>)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(i, v)| (Value::from(*i), Value::Bytes(v.clone())))
            .collect(),
    )
}

fn baseline() -> Map {
    vec![
        (
            Value::from("module_id"),
            Value::from("i-0123456789abcdef0-enc0123456789abcdef"),
        ),
        (Value::from("digest"), Value::from("SHA384")),
        (Value::from("timestamp"), Value::from(1_749_295_504_541_u64)),
        (
            Value::from("pcrs"),
            pcrs(&[(0, vec![1; 48]), (1, vec![2; 48]), (2, vec![3; 48])]),
        ),
        (Value::from("certificate"), Value::Bytes(vec![1; 64])),
        (
            Value::from("cabundle"),
            Value::Array(vec![Value::Bytes(vec![2; 64])]),
        ),
        (Value::from("public_key"), Value::Bytes(vec![3; 32])),
        (
            Value::from("user_data"),
            Value::Bytes(b"Hello, world!".to_vec()),
        ),
        (Value::from("nonce"), Value::Bytes(b"nonce".to_vec())),
    ]
}

fn with(key: &str, value: Value) -> Map {
    let mut map = without(key);
    map.push((Value::from(key), value));
    map
}

fn without(key: &str) -> Map {
    baseline()
        .into_iter()
        .filter(|(k, _)| *k != Value::from(key))
        .collect()
}

fn encode(map: Map) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Map(map), &mut out).expect("encoding cbor");
    out
}

#[test]
fn from_cbor_error_invalid_fields() {
    let too_many_pcrs: Vec<(u64, Vec<u8>)> = (0..33).map(|i| (i, vec![1; 48])).collect();
    let cases: Vec<(&str, Map, &str)> = vec![
        (
            "empty module_id",
            with("module_id", Value::from("")),
            "module_id",
        ),
        (
            "digest SHA256",
            with("digest", Value::from("SHA256")),
            "digest",
        ),
        (
            "timestamp 0",
            with("timestamp", Value::from(0_u64)),
            "timestamp",
        ),
        ("empty pcrs", with("pcrs", pcrs(&[])), "pcrs"),
        ("33 pcrs", with("pcrs", pcrs(&too_many_pcrs)), "pcrs"),
        (
            "pcr index 32",
            with("pcrs", pcrs(&[(32, vec![1; 48])])),
            "pcrs",
        ),
        (
            "pcr of 47 bytes",
            with("pcrs", pcrs(&[(0, vec![1; 47])])),
            "pcrs",
        ),
        (
            "empty certificate",
            with("certificate", Value::Bytes(vec![])),
            "certificate",
        ),
        (
            "certificate of 1025 bytes",
            with("certificate", Value::Bytes(vec![1; 1025])),
            "certificate",
        ),
        (
            "empty cabundle",
            with("cabundle", Value::Array(vec![])),
            "cabundle",
        ),
        (
            "cabundle entry of 1025 bytes",
            with("cabundle", Value::Array(vec![Value::Bytes(vec![1; 1025])])),
            "cabundle",
        ),
        (
            "empty public_key",
            with("public_key", Value::Bytes(vec![])),
            "public_key",
        ),
        (
            "user_data of 513 bytes",
            with("user_data", Value::Bytes(vec![1; 513])),
            "user_data",
        ),
        (
            "nonce of 513 bytes",
            with("nonce", Value::Bytes(vec![1; 513])),
            "nonce",
        ),
    ];

    for (name, map, field) in cases {
        // given
        let payload = encode(map);

        // when
        let result = AttestationDocument::from_cbor(&payload);

        // then
        assert_eq!(result, Err(Error::InvalidField(field)), "case: {name}");
    }
}

#[test]
fn from_cbor_error_missing_field() {
    // given
    let payload = encode(without("certificate"));

    // when
    let result = AttestationDocument::from_cbor(&payload);

    // then
    assert!(
        matches!(result, Err(Error::DecodingDocument(_))),
        "got {result:?}"
    );
}

#[test]
fn from_cbor_happy_path_null_optionals() {
    // given
    let mut map = with("public_key", Value::Null);
    for (k, v) in &mut map {
        if *k == Value::from("user_data") || *k == Value::from("nonce") {
            *v = Value::Null;
        }
    }
    let payload = encode(map);

    // when
    let doc = AttestationDocument::from_cbor(&payload).expect("parsing document");

    // then
    assert_eq!(doc.public_key, None);
    assert_eq!(doc.user_data, None);
    assert_eq!(doc.nonce, None);
}

#[test]
fn is_debug() {
    let cases: Vec<(&str, Value, bool)> = vec![
        (
            "all-zero PCR0-2",
            pcrs(&[
                (0, vec![0; 48]),
                (1, vec![0; 48]),
                (2, vec![0; 48]),
                (3, vec![1; 48]),
            ]),
            true,
        ),
        (
            "PCR1 non-zero",
            pcrs(&[(0, vec![0; 48]), (1, vec![1; 48]), (2, vec![0; 48])]),
            false,
        ),
        (
            "PCR2 missing",
            pcrs(&[(0, vec![0; 48]), (1, vec![0; 48])]),
            false,
        ),
    ];

    for (name, pcrs, want) in cases {
        // given
        let doc =
            AttestationDocument::from_cbor(&encode(with("pcrs", pcrs))).expect("parsing document");

        // when
        let got = doc.is_debug();

        // then
        assert_eq!(got, want, "case: {name}");
    }
}

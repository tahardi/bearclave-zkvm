use host::image_id_hex;
use nitro_verifier_methods::VERIFY_NITRO_ID;

#[test]
fn image_id_hex_happy_path() {
    // given
    let le_bytes: Vec<u8> = VERIFY_NITRO_ID
        .iter()
        .flat_map(|n| n.to_le_bytes())
        .collect();

    // when
    let got = image_id_hex();

    // then
    assert_eq!(got.len(), 64);
    assert!(got.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    assert_eq!(got, hex::encode(le_bytes));
}

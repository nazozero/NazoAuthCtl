use super::*;

#[test]
fn fragmented_json_retains_frames_and_matches_contiguous_parsing() {
    let raw = br#"{"plain":"hello","escaped":"a\n\u4e2d","nested":[1,true,null]}"#;
    let expected: serde_json::Value = serde_json::from_slice(raw).unwrap();
    for split in 1..raw.len() {
        let first = Bytes::copy_from_slice(&raw[..split]);
        let second = Bytes::copy_from_slice(&raw[split..]);
        let pointers = [first.as_ptr(), second.as_ptr()];
        let mut body = ResponseBody::from(first);
        body.push(Bytes::new());
        body.push(second);
        assert_eq!(body.len(), raw.len());
        assert!(!body.is_empty());
        assert_eq!(
            body.chunks().map(|b| b.as_ptr()).collect::<Vec<_>>(),
            pointers
        );
        assert_eq!(body.json::<serde_json::Value>().unwrap(), expected);
        assert_eq!(
            body.chunks().map(|b| b.as_ptr()).collect::<Vec<_>>(),
            pointers
        );
    }
    let mut body = ResponseBody::default();
    for byte in "{\"utf8\":\"中文🔑\"}".as_bytes() {
        body.push(Bytes::copy_from_slice(&[*byte]));
    }
    assert_eq!(
        body.json::<serde_json::Value>().unwrap(),
        serde_json::json!({"utf8":"中文🔑"})
    );
}

#[test]
fn json_requires_a_complete_single_value_across_frames() {
    for suffix in [b" true".as_slice(), b"{", b"\xff"] {
        let mut body = ResponseBody::from(Bytes::from_static(b"{}"));
        body.push(Bytes::copy_from_slice(suffix));
        assert!(body.json::<serde_json::Value>().is_err());
    }
    assert!(ResponseBody::default().is_empty());
    let body = ResponseBody::from(Bytes::from_static(b"html"));
    assert!(matches!(body.contiguous(), Cow::Borrowed(_)));
    let mut fragmented = body.clone();
    fragmented.push(Bytes::from_static(b" tail"));
    assert_eq!(fragmented.contiguous().as_ref(), b"html tail");
}

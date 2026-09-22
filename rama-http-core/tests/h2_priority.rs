//! Priority frames are observable through the public HTTP/2 client wire boundary.

use rama_core::{ServiceInput, bytes::Bytes, extensions::ExtensionsRef};
use rama_http_core::h2::client;
use rama_http_types::{
    Request,
    proto::h2::frame::{EarlyFrame, Priority, StreamDependency},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn client_replays_priority_frames_on_the_wire() {
    // Literal RFC 7540 payloads, including both encoded weight boundaries.
    for (dependency, weight, exclusive, expected) in [
        (0, 255, true, [0x80, 0, 0, 0, 255]),
        (31, 0, false, [0, 0, 0, 31, 0]),
        (0x0123_4567, 83, true, [0x81, 0x23, 0x45, 0x67, 83]),
    ] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (io, mut peer) = tokio::io::duplex(4096);
            let (mut sender, connection) = client::Builder::new()
                .with_early_frames(vec![EarlyFrame::Priority(Priority::new(
                    1.into(),
                    StreamDependency::new(dependency.into(), weight, exclusive),
                ))])
                .handshake::<_, Bytes>(ServiceInput::new(io))
                .await
                .unwrap();
            // Allocate the stream before driving the connection so replay can
            // refer to it. Keep its response alive throughout observation.
            let request = Request::builder()
                .uri("https://example.test/priority")
                .body(())
                .unwrap();
            let (_response, _body) = sender.send_request(request, true).unwrap();
            let observe = async {
                let mut preface = [0; 24];
                peer.read_exact(&mut preface).await.unwrap();
                assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
                // An empty server SETTINGS frame is sufficient for the peer.
                peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
                loop {
                    let mut header = [0; 9];
                    peer.read_exact(&mut header).await.unwrap();
                    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]);
                    let mut payload = vec![0; length as usize];
                    peer.read_exact(&mut payload).await.unwrap();
                    if header[3] == 2 {
                        assert_eq!(header, [0, 0, 5, 2, 0, 0, 0, 0, 1]);
                        assert_eq!(payload, expected);
                        break;
                    }
                }
            };
            tokio::select! {
                () = observe => {},
                result = connection => panic!("connection ended before PRIORITY: {result:?}"),
            }
        })
        .await
        .expect("priority replay timed out");
    }
}

#[tokio::test]
async fn request_headers_depend_on_the_nearest_live_weight_band() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (io, mut peer) = tokio::io::duplex(4096);
        let (mut sender, connection) = client::Builder::new()
            .handshake::<_, Bytes>(ServiceInput::new(io))
            .await
            .unwrap();
        let mut outstanding = Vec::new();
        for weight in [Some(100), Some(200), Some(200), None, Some(50), Some(255)] {
            let request = Request::builder()
                .uri("https://example.test/bands")
                .body(())
                .unwrap();
            if let Some(weight) = weight {
                request
                    .extensions()
                    .insert(client::RequestPriority::new(weight));
            }
            outstanding.push(sender.send_request(request, true).unwrap());
        }
        let observe = async {
            let mut preface = [0; 24];
            peer.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
            // High streams do not depend on a lower band. Equal peers chain;
            // the low stream selects band 100, not the most recent band 200.
            for (id, priority) in [
                (1, Some([0x80, 0, 0, 0, 100])),
                (3, Some([0x80, 0, 0, 0, 200])),
                (5, Some([0x80, 0, 0, 3, 200])),
                (7, None),
                (9, Some([0x80, 0, 0, 1, 50])),
                (11, Some([0x80, 0, 0, 0, 255])),
            ] {
                loop {
                    let (header, payload) = read_frame(&mut peer).await;
                    assert_ne!(header[3], 2, "initial priorities belong in HEADERS");
                    if header[3] != 1 {
                        continue;
                    }
                    assert_eq!(u32::from_be_bytes(header[5..].try_into().unwrap()), id);
                    assert_eq!(header[4] & 0x20 != 0, priority.is_some());
                    if let Some(priority) = priority {
                        assert_eq!(payload[..5], priority);
                    }
                    break;
                }
            }
        };
        tokio::select! {
            () = observe => {},
            result = connection => panic!("connection ended before HEADERS: {result:?}"),
        }
        drop(outstanding);
    })
    .await
    .expect("priority HEADERS timed out");
}

#[tokio::test]
async fn ordered_priority_changes_affect_the_next_headers_without_extra_frames() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (io, mut peer) = tokio::io::duplex(4096);
        let (mut sender, connection) = client::Builder::new()
            .handshake::<_, Bytes>(ServiceInput::new(io))
            .await
            .unwrap();
        let first = client::RequestPriority::new(100);
        let second = client::RequestPriority::new(100);
        let mut outstanding = Vec::new();
        for priority in [&first, &second] {
            outstanding.push(
                sender
                    .send_request(weighted_request(priority), true)
                    .unwrap(),
            );
        }
        let exercise = async {
            let mut preface = [0; 24];
            peer.read_exact(&mut preface).await.unwrap();
            peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
            for expected in [[0x80, 0, 0, 0, 100], [0x80, 0, 0, 1, 100]] {
                let payload = next_headers_without_priority_frame(&mut peer).await;
                assert_eq!(payload[..5], expected);
            }
            // These promotions change neither stream's parent, so they emit
            // no PRIORITY frames. Their order still determines the next parent.
            first.set_weight(200);
            second.set_weight(200);
            outstanding.push(
                sender
                    .send_request(weighted_request(&client::RequestPriority::new(200)), true)
                    .unwrap(),
            );
            let payload = next_headers_without_priority_frame(&mut peer).await;
            assert_eq!(payload[..5], [0x80, 0, 0, 3, 200]);
        };
        tokio::select! {
            () = exercise => {},
            result = connection => panic!("connection ended during promotion: {result:?}"),
        }
    })
    .await
    .expect("priority changes timed out");
}

#[tokio::test]
async fn reprioritization_reconnects_the_old_child_before_later_headers() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (io, mut peer) = tokio::io::duplex(4096);
        let (mut sender, connection) = client::Builder::new()
            .handshake::<_, Bytes>(ServiceInput::new(io))
            .await
            .unwrap();
        let moved = client::RequestPriority::new(100);
        let mut outstanding = Vec::new();
        for priority in [
            &moved,
            &client::RequestPriority::new(200),
            &client::RequestPriority::new(100),
        ] {
            outstanding.push(
                sender
                    .send_request(weighted_request(priority), true)
                    .unwrap(),
            );
        }
        let exercise = async {
            let mut preface = [0; 24];
            peer.read_exact(&mut preface).await.unwrap();
            peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
            for expected in [
                [0x80, 0, 0, 0, 100],
                [0x80, 0, 0, 0, 200],
                [0x80, 0, 0, 1, 100],
            ] {
                assert_eq!(
                    next_headers_without_priority_frame(&mut peer).await[..5],
                    expected
                );
            }
            moved.set_weight(255);
            outstanding.push(
                sender
                    .send_request(weighted_request(&client::RequestPriority::new(255)), true)
                    .unwrap(),
            );
            // Move stream 1 ahead of stream 3. Reconnect its old child 5 to
            // old parent 3, then move 1 to root, all before the new HEADERS.
            for (id, expected) in [(5, [0x80, 0, 0, 3, 100]), (1, [0x80, 0, 0, 0, 255])] {
                loop {
                    let (header, payload) = read_frame(&mut peer).await;
                    if header[3] == 4 {
                        continue;
                    }
                    assert_eq!(header, [0, 0, 5, 2, 0, 0, 0, 0, id]);
                    assert_eq!(payload, expected);
                    break;
                }
            }
            assert_eq!(
                next_headers_without_priority_frame(&mut peer).await[..5],
                [0x80, 0, 0, 1, 255]
            );
        };
        tokio::select! {
            () = exercise => {},
            result = connection => panic!("connection ended during reprioritization: {result:?}"),
        }
    })
    .await
    .expect("reprioritization timed out");
}

#[tokio::test]
async fn changes_before_first_poll_only_affect_initial_headers() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (io, mut peer) = tokio::io::duplex(4096);
        let (mut sender, connection) = client::Builder::new()
            .handshake::<_, Bytes>(ServiceInput::new(io))
            .await
            .unwrap();
        let priority = client::RequestPriority::new(10);
        let _first = sender
            .send_request(weighted_request(&client::RequestPriority::new(100)), true)
            .unwrap();
        let _second = sender
            .send_request(weighted_request(&priority), true)
            .unwrap();
        // The same controller may not bind two simultaneous streams.
        sender
            .send_request(weighted_request(&priority), true)
            .expect_err("one priority control cannot bind concurrent streams");
        priority.set_weight(200);
        priority.set_weight(100);
        priority.set_weight(200);
        let exercise = async {
            let mut preface = [0; 24];
            peer.read_exact(&mut preface).await.unwrap();
            peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
            for expected in [[0x80, 0, 0, 0, 100], [0x80, 0, 0, 0, 200]] {
                assert_eq!(
                    next_headers_without_priority_frame(&mut peer).await[..5],
                    expected
                );
            }
        };
        tokio::select! {
            () = exercise => {},
            result = connection => panic!("connection ended before initial HEADERS: {result:?}"),
        }
    })
    .await
    .expect("pending priority changes timed out");
}

#[tokio::test]
async fn closed_streams_are_not_parents_and_controls_can_bind_a_retry() {
    for reset in [false, true] {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (io, mut peer) = tokio::io::duplex(4096);
            let (mut sender, connection) = client::Builder::new()
                .handshake::<_, Bytes>(ServiceInput::new(io))
                .await
                .unwrap();
            let old = client::RequestPriority::new(100);
            let _first = sender
                .send_request(weighted_request(&client::RequestPriority::new(100)), true)
                .unwrap();
            let (response, mut body) = sender.send_request(weighted_request(&old), true).unwrap();
            let exercise = async {
                let mut preface = [0; 24];
                peer.read_exact(&mut preface).await.unwrap();
                peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
                for expected in [[0x80, 0, 0, 0, 100], [0x80, 0, 0, 1, 100]] {
                    assert_eq!(
                        next_headers_without_priority_frame(&mut peer).await[..5],
                        expected
                    );
                }
                let completed = if reset {
                    body.send_reset(rama_http_core::h2::Reason::CANCEL);
                    assert_eq!(
                        response.await.expect_err("reset response").reason(),
                        Some(rama_http_core::h2::Reason::CANCEL),
                    );
                    None
                } else {
                    // Status 200, END_HEADERS | END_STREAM. Awaiting the
                    // response proves the client processed FIN, not just the peer.
                    peer.write_all(&[0, 0, 1, 1, 5, 0, 0, 0, 3, 0x88])
                        .await
                        .unwrap();
                    Some(response.await.unwrap())
                };
                old.set_weight(255); // Must not revive the closed stream.
                let _next = sender
                    .send_request(weighted_request(&client::RequestPriority::new(100)), true)
                    .unwrap();
                assert_eq!(
                    next_headers_without_priority_frame(&mut peer).await[..5],
                    [0x80, 0, 0, 1, 100]
                );
                // Reuse on a later attempt, with the latest value, while the
                // completed response and send handle still exist.
                let _retry = sender.send_request(weighted_request(&old), true).unwrap();
                assert_eq!(
                    next_headers_without_priority_frame(&mut peer).await[..5],
                    [0x80, 0, 0, 0, 255]
                );
                let _last = sender
                    .send_request(weighted_request(&client::RequestPriority::new(255)), true)
                    .unwrap();
                assert_eq!(
                    next_headers_without_priority_frame(&mut peer).await[..5],
                    [0x80, 0, 0, 7, 255]
                );
                drop(completed);
            };
            tokio::select! {
                () = exercise => {},
                result = connection => panic!("connection ended during stream closure: {result:?}"),
            }
        })
        .await
        .expect("stream closure test timed out");
    }
}

#[tokio::test]
async fn priority_prefix_does_not_corrupt_fragmented_hpack() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (io, mut peer) = tokio::io::duplex(128);
        let (mut sender, connection) = client::Builder::new()
            .handshake::<_, Bytes>(ServiceInput::new(io))
            .await
            .unwrap();
        let value = "0123456789abcdef".repeat(5000);
        let mut request = weighted_request(&client::RequestPriority::new(100));
        request
            .headers_mut()
            .insert("x-fragmented", value.parse().unwrap());
        let _response = sender.send_request(request, true).unwrap();
        let exercise = async {
            let mut preface = [0; 24];
            peer.read_exact(&mut preface).await.unwrap();
            peer.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
            let mut block = rama_core::bytes::BytesMut::new();
            let mut fragments = 0;
            loop {
                let (header, payload) = read_frame(&mut peer).await;
                if header[3] == 4 && fragments == 0 {
                    continue;
                }
                assert_eq!(&header[5..], &[0, 0, 0, 1]);
                assert!(payload.len() <= 16384);
                if fragments == 0 {
                    assert_eq!(header[3], 1);
                    assert_ne!(header[4] & 0x20, 0);
                    assert_eq!(payload[..5], [0x80, 0, 0, 0, 100]);
                    block.extend_from_slice(&payload[5..]);
                } else {
                    assert_eq!(header[3], 9);
                    assert_eq!(header[4] & 0x20, 0);
                    block.extend_from_slice(&payload);
                }
                fragments += 1;
                if header[4] & 4 != 0 {
                    break;
                }
            }
            assert!(fragments > 1, "fixture must exercise CONTINUATION");
            let mut decoded = Vec::new();
            rama_http_types::proto::h2::hpack::Decoder::new(4096)
                .decode(&mut std::io::Cursor::new(&mut block), |header| {
                    decoded.push(header);
                    std::ops::ControlFlow::Continue(())
                })
                .unwrap();
            assert!(
                decoded.contains(&rama_http_types::proto::h2::hpack::Header::Field {
                    name: "x-fragmented".parse().unwrap(),
                    value: value.parse().unwrap(),
                })
            );
        };
        tokio::select! {
            () = exercise => {},
            result = connection => panic!("connection ended during HPACK: {result:?}"),
        }
    })
    .await
    .expect("fragmented priority HEADERS timed out");
}

#[cfg(test)]
fn weighted_request(priority: &client::RequestPriority) -> Request<()> {
    let request = Request::builder()
        .uri("https://example.test/weighted")
        .body(())
        .unwrap();
    request.extensions().insert(priority.clone());
    request
}

async fn next_headers_without_priority_frame(peer: &mut tokio::io::DuplexStream) -> Vec<u8> {
    loop {
        let (header, payload) = read_frame(peer).await;
        assert_ne!(header[3], 2, "parent did not change; no PRIORITY expected");
        if header[3] == 1 {
            assert_ne!(header[4] & 0x20, 0);
            return payload;
        }
    }
}

#[cfg(test)]
async fn read_frame(peer: &mut tokio::io::DuplexStream) -> ([u8; 9], Vec<u8>) {
    let mut header = [0; 9];
    peer.read_exact(&mut header).await.unwrap();
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]);
    let mut payload = vec![0; length as usize];
    peer.read_exact(&mut payload).await.unwrap();
    (header, payload)
}

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::io::{Cursor, Write};

use rustls::error::{AlertDescription, ApiMisuse, InvalidMessage};
use rustls::split::{ReceiveTraffic, ReceiveTrafficState, SplitConnection};
use rustls::{Connection, Error, SideData, SliceInput, TlsInputBuffer};
use rustls_test::{KeyType, do_handshake, make_pair};

#[test]
fn split_pairwise() {
    let (mut client, mut server) =
        make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

    let client_split = client.split().unwrap();
    println!("{client_split:?}");

    let SplitConnection {
        send: mut client_send,
        receive: mut client_recv,
        outputs: client_outputs,
    } = client_split;
    let SplitConnection {
        send: mut server_send,
        receive: mut server_recv,
        outputs: server_outputs,
    } = server.split().unwrap();

    assert_eq!(
        client_outputs.alpn_protocol(),
        server_outputs.alpn_protocol()
    );
    assert_eq!(
        client_outputs.handshake_kind(),
        server_outputs.handshake_kind()
    );
    assert_eq!(
        client_outputs.protocol_version(),
        server_outputs.protocol_version()
    );
    assert_eq!(
        client_outputs.negotiated_cipher_suite(),
        server_outputs.negotiated_cipher_suite()
    );
    assert_eq!(
        client_outputs
            .negotiated_key_exchange_group()
            .map(|kxg| kxg.name()),
        server_outputs
            .negotiated_key_exchange_group()
            .map(|kxg| kxg.name()),
    );

    let flight = client_send
        .write(b"client to server".as_slice().into())
        .unwrap();
    server_recv = check_received(server_recv, flight, b"client to server");

    let flight = server_send
        .write(b"server to client".as_slice().into())
        .unwrap();
    client_recv = check_received(client_recv, flight, b"server to client");

    check_closed(server_recv, client_send.close());
    check_closed(client_recv, server_send.close());
}

#[test]
fn split_client_tickets_received() {
    let (mut client, mut server) =
        make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

    assert_eq!(
        client
            .split()
            .unwrap()
            .receive
            .tls13_tickets_received(),
        2
    );
}

#[test]
fn split_fails_during_handshake() {
    let (client, server) = make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
    assert_eq!(
        client.split().err(),
        Some(Error::ApiMisuse(ApiMisuse::SplitDuringHandshake))
    );
    assert_eq!(
        server.split().err(),
        Some(Error::ApiMisuse(ApiMisuse::SplitDuringHandshake))
    );
}

#[test]
fn split_fails_with_pending_plaintext() {
    let (mut client, mut server) =
        make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
    assert_eq!(client.writer().write(b"huh").unwrap(), 3);
    assert_eq!(server.writer().write(b"hmm").unwrap(), 3);
    do_handshake(&mut client, &mut server);

    assert_eq!(
        server.split().err(),
        Some(Error::ApiMisuse(ApiMisuse::SplitWithPendingBuffers))
    );
    assert_eq!(
        client.split().err(),
        Some(Error::ApiMisuse(ApiMisuse::SplitWithPendingBuffers))
    );
}

#[test]
fn key_update() {
    let (mut client, mut server) =
        make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

    let SplitConnection {
        send: mut client_send,
        receive: client_recv,
        ..
    } = client.split().unwrap();
    let SplitConnection {
        send: mut server_send,
        receive: mut server_recv,
        ..
    } = server.split().unwrap();

    client_send
        .refresh_traffic_keys()
        .unwrap();
    server_recv = check_service_sender(server_recv, client_send.take_data().unwrap());

    let flight = server_send
        .write(b"server to client".as_slice().into())
        .unwrap();
    check_received(client_recv, flight, b"server to client");

    let flight = client_send
        .write(b"client to server".as_slice().into())
        .unwrap();
    check_received(server_recv, flight, b"client to server");
}

#[test]
fn read_invalid_data_and_send_alert() {
    let (mut client, mut server) =
        make_pair(KeyType::EcdsaP256, &super::provider::DEFAULT_PROVIDER);
    do_handshake(&mut client, &mut server);

    let receive = client.split().unwrap().receive;

    let mut err = receive
        .read(&mut SliceInput::new(&mut [0u8; 5]))
        .err()
        .unwrap();
    let data = err.take_tls_data().unwrap();
    assert_eq!(
        err.error,
        Error::InvalidMessage(InvalidMessage::InvalidContentType)
    );

    server
        .read_tls(&mut Cursor::new(data))
        .unwrap();
    assert_eq!(
        server.process_new_packets().err(),
        Some(Error::AlertReceived(AlertDescription::DecodeError))
    );
}

fn check_received<Side: SideData>(
    mut recv: ReceiveTraffic<Side>,
    flight: Vec<Vec<u8>>,
    expected: &[u8],
) -> ReceiveTraffic<Side> {
    for mut chunk in flight {
        let mut inp = SliceInput::new(&mut chunk);
        recv = match recv.read(&mut inp).unwrap() {
            ReceiveTrafficState::ReadMore(recv) => recv,
            ReceiveTrafficState::ServiceSender(_service_sender) => unreachable!(),
            ReceiveTrafficState::Available(mut received) => {
                assert_eq!(received.data(), expected);
                received.into_next()
            }
            ReceiveTrafficState::CloseNotify => unreachable!(),
        };
        assert_eq!(inp.into_used(), chunk.len());
    }
    recv
}

fn check_closed<Side: SideData>(recv: ReceiveTraffic<Side>, mut flight: Vec<u8>) {
    let mut inp = SliceInput::new(&mut flight);
    let r = recv.read(&mut inp);
    let Ok(ReceiveTrafficState::CloseNotify) = r else {
        panic!("check_closed failed {r:?}");
    };
}

fn check_service_sender<Side: SideData>(
    recv: ReceiveTraffic<Side>,
    mut flight: Vec<u8>,
) -> ReceiveTraffic<Side> {
    let mut inp = SliceInput::new(&mut flight);
    let r = recv.read(&mut inp);
    let Ok(ReceiveTrafficState::ServiceSender(wake)) = r else {
        panic!("check_service_sender failed: {r:?}");
    };
    assert_eq!(inp.into_used(), flight.len());
    wake.into_next()
}

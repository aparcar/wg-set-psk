use anyhow;

use base64::{engine::general_purpose, Engine as _};
use std::env;

use wireguard_uapi::DeviceInterface;
use wireguard_uapi::WgSocket;

use std::io;

fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();

    let interface: &String = &args[1];
    let peer_pubkey: &String = &args[2];

    let mut pks_buf: String = String::new();
    let stdin = io::stdin();
    stdin.read_line(&mut pks_buf)?;

    let mut wg = WgSocket::connect()?;
    let device = wg.get_device(DeviceInterface::from_name(interface))?;
    let mut peer_pubkey_decoded: [u8; 32] = [0; 32];
    let mut psk: [u8; 32] = [0; 32];
    general_purpose::STANDARD.decode_slice(peer_pubkey, &mut peer_pubkey_decoded);
    general_purpose::STANDARD.decode_slice(pks_buf, &mut psk);

    if device
        .peers
        .iter()
        .find(|p| &p.public_key == &peer_pubkey_decoded)
        .is_none()
    {
        panic!("Peer not found")
    }

    let mut set_peer = wireguard_uapi::set::Peer::from_public_key(&peer_pubkey_decoded);
    set_peer
        .flags
        .push(wireguard_uapi::set::WgPeerF::UpdateOnly);
    set_peer.preshared_key = Some(&psk);
    let mut set_dev = wireguard_uapi::set::Device::from_ifname(interface);
    set_dev.peers.push(set_peer);

    wg.set_device(set_dev)?;
    Ok(())
}

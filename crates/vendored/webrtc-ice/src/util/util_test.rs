use super::*;

#[tokio::test]
async fn test_local_interfaces() -> Result<()> {
    let vnet = Arc::new(Net::new(None));
    let interfaces = vnet.get_interfaces().await;
    let ips = local_interfaces(
        &vnet,
        &None,
        &None,
        &[NetworkType::Udp4, NetworkType::Udp6],
        false,
    )
    .await;

    let ips_with_loopback = local_interfaces(
        &vnet,
        &None,
        &None,
        &[NetworkType::Udp4, NetworkType::Udp6],
        true,
    )
    .await;
    assert!(ips_with_loopback.is_superset(&ips));
    assert!(!ips.iter().any(|ip| ip.is_loopback()));
    assert!(ips_with_loopback.iter().any(|ip| ip.is_loopback()));
    assert!(
        !ips_with_loopback
            .iter()
            .any(|ip| matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())),
        "local_interfaces returns unscoped IpAddr values and must never include fe80::/10 link-local addresses"
    );
    log::info!(
        "interfaces: {:?}, ips: {:?}, ips_with_loopback: {:?}",
        interfaces,
        ips,
        ips_with_loopback
    );
    Ok(())
}

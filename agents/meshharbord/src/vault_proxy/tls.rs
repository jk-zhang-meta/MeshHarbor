// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-5b — TLS to a vault proxy's upstream, always verified: against
//! the system's roots (a corporate CA in the OS store included, as the
//! daemon's own WS path trusts it), and a CA the secret may hold.
//!
//! ⚠️ Never unverified. A proxy authenticates with a value, and a value
//! presented to an upstream nobody verified is presented to whoever
//! answered.

use std::sync::Arc;

use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};

/// A connector that trusts the system's roots, and `ca` (PEM, one or more
/// certificates) when the secret holds one: the tests' shorthand. The
/// endpoint reads the roots once (`roots`) and makes its connectors over
/// them (`connector_for`), since a client certificate needs one per
/// connection (P3-5e-2).
#[cfg(test)]
pub(crate) fn connector(ca: Option<&str>) -> Result<TlsConnector, String> {
    connector_for(roots(ca)?, None)
}

/// P3-5e-1 — a client certificate's chain and its key, as TLS presents them
/// to an upstream that asks for one (a Kubernetes API server, most often).
pub(crate) struct Identity {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

/// An identity from the secret's `cert` (PEM: the certificate, then any
/// intermediates) and `key` (PEM: PKCS#8, PKCS#1 or SEC1).
pub(crate) fn identity(cert: &str, key: &str) -> Result<Identity, String> {
    let chain = CertificateDer::pem_slice_iter(cert.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("the secret's client certificate does not read as PEM: {e}"))?;
    if chain.is_empty() {
        return Err("the secret's client certificate holds no certificate".into());
    }
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes())
        .map_err(|e| format!("the secret's key does not read as a PEM private key: {e}"))?;
    Ok(Identity { chain, key })
}

/// A connector that verifies against `roots`, and presents `identity` where
/// one is given (P3-5e-1). Built for each connection that presents one, so
/// a key lives only in that connection's TLS.
pub(crate) fn connector_for(
    roots: Arc<RootCertStore>,
    identity: Option<Identity>,
) -> Result<TlsConnector, String> {
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots);
    let config = match identity {
        None => builder.with_no_client_auth(),
        Some(Identity { chain, key }) => builder.with_client_auth_cert(chain, key).map_err(|e| {
            format!("the secret's client certificate and key are not an identity TLS can present: {e}")
        })?,
    };
    Ok(TlsConnector::from(Arc::new(config)))
}

/// The roots an upstream is verified against: the system's, and `ca` (PEM,
/// one or more certificates) when the secret holds one.
pub(crate) fn roots(ca: Option<&str>) -> Result<Arc<RootCertStore>, String> {
    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        // One root the store cannot take is not a reason to trust none.
        let _ = roots.add(cert);
    }
    if let Some(pem) = ca {
        let mut added = 0;
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert = cert.map_err(|e| format!("the secret's CA does not read as PEM: {e}"))?;
            roots
                .add(cert)
                .map_err(|e| format!("the secret's CA is not a certificate TLS can trust: {e}"))?;
            added += 1;
        }
        if added == 0 {
            return Err("the secret's CA holds no certificate".into());
        }
    }
    if roots.is_empty() {
        return Err("no root to verify an upstream against".into());
    }
    Ok(Arc::new(roots))
}

/// The name the upstream's certificate must carry: a DNS name or an IP
/// address.
pub(crate) fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(host.to_string())
        .map_err(|_| format!("{host} is not a name a certificate can carry"))
}

/// The hash a certificate's signature algorithm names, by its OID as DER
/// holds it (RFC 5929 §4.1: MD5 and SHA-1 become SHA-256).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hash {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

const SIGNATURE_HASHES: [(&[u8], Hash); 12] = [
    // md5WithRSAEncryption, sha1WithRSAEncryption: SHA-256 for both.
    (
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04],
        Hash::Sha256,
    ),
    (
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05],
        Hash::Sha256,
    ),
    // sha256-, sha384-, sha512-, sha224WithRSAEncryption.
    (
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
        Hash::Sha256,
    ),
    (
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C],
        Hash::Sha384,
    ),
    (
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D],
        Hash::Sha512,
    ),
    (
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0E],
        Hash::Sha224,
    ),
    // ecdsa-with-SHA1: SHA-256.
    (&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01], Hash::Sha256),
    // ecdsa-with-SHA224, -SHA256, -SHA384, -SHA512.
    (
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x01],
        Hash::Sha224,
    ),
    (
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02],
        Hash::Sha256,
    ),
    (
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03],
        Hash::Sha384,
    ),
    (
        &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04],
        Hash::Sha512,
    ),
    // dsa-with-SHA256.
    (
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02],
        Hash::Sha256,
    ),
];

/// P3-5b-3 — RFC 5929's `tls-server-end-point`: the upstream's certificate
/// hashed with the hash its signature algorithm names. `None` where the RFC
/// leaves it undefined (an algorithm with no single hash: Ed25519, RSASSA-PSS)
/// or the certificate does not read; the proxy then does not bind.
pub(crate) fn server_end_point(cert: &CertificateDer<'_>) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
    let der = cert.as_ref();
    let oid = signature_algorithm(der)?;
    let (_, hash) = SIGNATURE_HASHES.iter().find(|(o, _)| *o == oid)?;
    Some(match hash {
        Hash::Sha224 => Sha224::digest(der).to_vec(),
        Hash::Sha256 => Sha256::digest(der).to_vec(),
        Hash::Sha384 => Sha384::digest(der).to_vec(),
        Hash::Sha512 => Sha512::digest(der).to_vec(),
    })
}

/// The certificate's `signatureAlgorithm`, as its OID's bytes:
/// `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, … }`, the
/// algorithm the first field of its `AlgorithmIdentifier`.
fn signature_algorithm(der: &[u8]) -> Option<&[u8]> {
    const SEQUENCE: u8 = 0x30;
    const OID: u8 = 0x06;
    let (SEQUENCE, certificate, _) = tlv(der)? else {
        return None;
    };
    let (SEQUENCE, _tbs, rest) = tlv(certificate)? else {
        return None;
    };
    let (SEQUENCE, algorithm, _) = tlv(rest)? else {
        return None;
    };
    let (OID, oid, _) = tlv(algorithm)? else {
        return None;
    };
    Some(oid)
}

/// One DER element off the front of `b`: its tag, its contents, and what
/// follows it. `None` for a length that does not fit or is not DER's.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |len, b| (len << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256, Sha384, Sha512};

    use super::*;

    /// A certificate's shape around `oid`: what the walk reads, and nothing
    /// a real one would need besides.
    fn shaped(oid: &[u8]) -> Vec<u8> {
        let mut algorithm = vec![0x06, oid.len() as u8];
        algorithm.extend(oid);
        let mut body = vec![0x30, 0x00];
        body.extend([0x30, algorithm.len() as u8]);
        body.extend(&algorithm);
        body.extend([0x03, 0x01, 0x00]);
        let mut der = vec![0x30, body.len() as u8];
        der.extend(body);
        der
    }

    /// Real certificates, made here: ECDSA over P-256 hashes with SHA-256,
    /// over P-384 with SHA-384; Ed25519 names no hash, so it binds nothing.
    #[test]
    fn a_certificate_binds_by_the_hash_its_signature_names() {
        let made = |alg: &'static rcgen::SignatureAlgorithm| {
            let key = rcgen::KeyPair::generate_for(alg).unwrap();
            rcgen::CertificateParams::new(vec!["localhost".to_string()])
                .unwrap()
                .self_signed(&key)
                .unwrap()
                .der()
                .clone()
        };
        let p256 = made(&rcgen::PKCS_ECDSA_P256_SHA256);
        assert_eq!(
            server_end_point(&p256),
            Some(Sha256::digest(&p256).to_vec())
        );
        let p384 = made(&rcgen::PKCS_ECDSA_P384_SHA384);
        assert_eq!(
            server_end_point(&p384),
            Some(Sha384::digest(&p384).to_vec())
        );
        assert_eq!(server_end_point(&made(&rcgen::PKCS_ED25519)), None);
    }

    /// The hash each signature algorithm names, MD5 and SHA-1 made SHA-256;
    /// an algorithm with no single hash, or none the table knows, binds
    /// nothing, and a certificate that does not read binds nothing.
    #[test]
    fn the_hash_follows_rfc_5929() {
        let sha1_rsa = shaped(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05]);
        let bound = server_end_point(&CertificateDer::from(sha1_rsa.clone())).unwrap();
        assert_eq!(
            bound,
            Sha256::digest(&sha1_rsa).to_vec(),
            "SHA-1 becomes SHA-256"
        );
        let sha512_ecdsa = shaped(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04]);
        let bound = server_end_point(&CertificateDer::from(sha512_ecdsa.clone())).unwrap();
        assert_eq!(bound, Sha512::digest(&sha512_ecdsa).to_vec());
        // RSASSA-PSS: its hash is in its parameters, more than one hash.
        let pss = shaped(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A]);
        assert_eq!(server_end_point(&CertificateDer::from(pss)), None);
        for broken in [
            vec![],
            vec![0x30],
            vec![0x30, 0x05, 0x30, 0x00],
            vec![0x31, 0x00],
            vec![0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
            shaped(&[]),
        ] {
            assert_eq!(
                server_end_point(&CertificateDer::from(broken.clone())),
                None,
                "{broken:02x?}"
            );
        }
    }
}

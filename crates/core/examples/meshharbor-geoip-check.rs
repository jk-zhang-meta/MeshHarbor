// SPDX-License-Identifier: AGPL-3.0-only
// Validate a candidate Country MMDB before replacing the deployed database.

use maxminddb::{Reader, geoip2};
use meshharbor_core::business_authority::MAX_GEOIP_DATASET_AGE_SECS;
use serde_json::{Value, json};
use std::{net::IpAddr, path::Path, process::ExitCode, time::SystemTime};

fn country_lookup(reader: &Reader<Vec<u8>>, address: &str) -> bool {
    let address: IpAddr = address.parse().expect("static probe address");
    reader
        .lookup::<geoip2::Country<'_>>(address)
        .ok()
        .and_then(|record| record.country)
        .and_then(|country| country.iso_code)
        .is_some_and(|code| code.len() == 2 && code.bytes().all(|byte| byte.is_ascii_uppercase()))
}

fn inspect(reader: &Reader<Vec<u8>>, now: u64) -> Value {
    let metadata = &reader.metadata;
    let age = now.checked_sub(metadata.build_epoch);
    let ipv4_ok = country_lookup(reader, "8.8.8.8");
    let ipv6_ok = metadata.ip_version == 6 && country_lookup(reader, "2001:4860:4860::8888");
    let status = if !matches!(
        metadata.database_type.as_str(),
        "DBIP-Country-Lite" | "GeoLite2-Country" | "GeoIP2-Country"
    ) {
        "unsupported_database_type"
    } else if metadata.ip_version != 6 {
        "unsupported_ip_version"
    } else if metadata.binary_format_major_version != 2 {
        "unsupported_binary_format"
    } else if metadata.build_epoch == 0 {
        "invalid_build_epoch"
    } else if metadata.build_epoch > now {
        "future_build"
    } else if age.is_some_and(|age| age > MAX_GEOIP_DATASET_AGE_SECS) {
        "expired"
    } else if !ipv4_ok || !ipv6_ok {
        "invalid_country_data"
    } else {
        "current"
    };
    json!({
        "valid": status == "current", "status": status,
        "database_type": metadata.database_type, "build_epoch": metadata.build_epoch,
        "ip_version": metadata.ip_version, "node_count": metadata.node_count,
        "record_size": metadata.record_size,
        "binary_format_major_version": metadata.binary_format_major_version,
        "binary_format_minor_version": metadata.binary_format_minor_version,
        "checked_at_epoch": now, "age_secs": age,
        "max_age_secs": MAX_GEOIP_DATASET_AGE_SECS,
        "ipv4_lookup_ok": ipv4_ok, "ipv6_lookup_ok": ipv6_ok,
    })
}

fn check(path: &Path, now: u64) -> Value {
    match Reader::open_readfile(path) {
        Ok(reader) => inspect(&reader, now),
        Err(_) => json!({"valid": false, "status": "invalid_mmdb"}),
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let path = args.next();
    let report = match (path, args.next()) {
        (Some(path), None) => match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(now) => check(Path::new(&path), now.as_secs()),
            Err(_) => json!({"valid": false, "status": "invalid_clock"}),
        },
        _ => json!({"valid": false, "status": "invalid_arguments",
            "usage": "meshharbor-geoip-check <database.mmdb>"}),
    };
    let valid = report["valid"] == true;
    println!("{report}");
    ExitCode::from(u8::from(!valid))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The existing user_analytics test fixture's real MMDB encoding, with
    // configurable metadata and an IPv6 tree that also resolves IPv4.
    fn database(database_type: &str, epoch: u64, ip_version: u16, code: &str) -> Vec<u8> {
        fn text(out: &mut Vec<u8>, value: &str) {
            out.push(0x40 | value.len() as u8);
            out.extend_from_slice(value.as_bytes());
        }
        fn uint16(out: &mut Vec<u8>, value: u16) {
            out.push(0xA2);
            out.extend_from_slice(&value.to_be_bytes());
        }
        let mut country = vec![0xE1];
        text(&mut country, "country");
        country.push(0xE1);
        text(&mut country, "iso_code");
        text(&mut country, code);
        let mut db = Vec::new();
        for _ in 0..2 {
            db.extend_from_slice(&17u32.to_be_bytes()[1..]);
        }
        db.extend_from_slice(&[0; 16]);
        db.extend_from_slice(&country);
        db.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
        db.push(0xE9);
        text(&mut db, "binary_format_major_version");
        uint16(&mut db, 2);
        text(&mut db, "binary_format_minor_version");
        uint16(&mut db, 0);
        text(&mut db, "build_epoch");
        db.extend_from_slice(&[0x08, 2]);
        db.extend_from_slice(&epoch.to_be_bytes());
        text(&mut db, "database_type");
        text(&mut db, database_type);
        text(&mut db, "description");
        db.push(0xE1);
        text(&mut db, "en");
        text(&mut db, "fixture");
        text(&mut db, "ip_version");
        uint16(&mut db, ip_version);
        text(&mut db, "languages");
        db.extend_from_slice(&[0x01, 4]);
        text(&mut db, "en");
        text(&mut db, "node_count");
        db.push(0xC4);
        db.extend_from_slice(&1u32.to_be_bytes());
        text(&mut db, "record_size");
        uint16(&mut db, 24);
        db
    }

    fn report(kind: &str, epoch: u64, version: u16, code: &str, now: u64) -> Value {
        let reader = Reader::from_source(database(kind, epoch, version, code)).unwrap();
        inspect(&reader, now)
    }

    #[test]
    fn real_reader_checks_exact_security_freshness_boundaries() {
        let now = 1_800_000_000;
        for age in [0, MAX_GEOIP_DATASET_AGE_SECS] {
            assert_eq!(
                report("DBIP-Country-Lite", now - age, 6, "US", now)["status"],
                "current"
            );
        }
        let expired = report(
            "DBIP-Country-Lite",
            now - MAX_GEOIP_DATASET_AGE_SECS - 1,
            6,
            "US",
            now,
        );
        assert_eq!(expired["status"], "expired");
        assert_eq!(expired["valid"], false);
        assert_eq!(expired["build_epoch"], now - MAX_GEOIP_DATASET_AGE_SECS - 1);
        for (epoch, status) in [
            (0, "invalid_build_epoch"),
            (now + 1, "future_build"),
            (u64::MAX, "future_build"),
        ] {
            assert_eq!(
                report("DBIP-Country-Lite", epoch, 6, "US", now)["status"],
                status
            );
        }
    }

    #[test]
    fn country_schema_and_both_address_families_are_required() {
        let now = 1_800_000_000;
        let valid = report("DBIP-Country-Lite", now, 6, "US", now);
        assert_eq!(valid["ipv4_lookup_ok"], true);
        assert_eq!(valid["ipv6_lookup_ok"], true);
        assert_eq!(
            report("DBIP-ASN-Lite", now, 6, "US", now)["status"],
            "unsupported_database_type"
        );
        assert_eq!(
            report("DBIP-Country-Lite", now, 4, "US", now)["status"],
            "unsupported_ip_version"
        );
        assert_eq!(
            report("DBIP-Country-Lite", now, 6, "??", now)["status"],
            "invalid_country_data"
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("invalid.mmdb");
        std::fs::write(&path, b"not a database").unwrap();
        assert_eq!(check(&path, now)["status"], "invalid_mmdb");
        assert_eq!(
            check(&directory.path().join("missing.mmdb"), now)["valid"],
            false
        );
    }
}

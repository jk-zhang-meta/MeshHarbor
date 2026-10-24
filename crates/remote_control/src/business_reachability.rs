// SPDX-License-Identifier: MPL-2.0
//! Shared business-reachability decision for MeshHarbor v039.
//!
//! This is a pure policy module, not a wire verifier or a URL parser. Callers
//! MUST first authenticate the center/peer, verify signed claims or trusted
//! database/registered-router output, bind the original session principal, and
//! parse targets with the SAME URL parser used by their dialer. These input
//! types deliberately have no Deserialize implementation: a client report is
//! not center authority. `Authority::CenterAuthenticated` is a typed statement
//! about that preceding verification, not something this module can prove.
//!
//! Reuse `BusinessReachability::decide` for discovery, full/delta netmaps,
//! grants, forwarding admission and native ingress. Applying it only to a UI
//! list does not provide the hard guarantee. Runtime integration, cryptographic
//! issuance/verification, source-IP/GeoIP lookup, session revocation and native
//! collection/application remain caller responsibilities and are not claimed
//! implemented by this standalone candidate.

use std::net::IpAddr;

pub const MANAGEMENT_HOST: &str = "www.itachi.fans";
pub const MAX_MANAGED_HOPS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Zone { Mainland, NonMainland }

/// Only a center-approved role distinguishes a client from a server. An agent
/// enrollment, OS type or a forwarding process is NOT a server-role assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceRole { Client, Server, Unknown }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authority { CenterAuthenticated, UntrustedReport }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revocation { Active, Revoked }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context { pub now: u64, pub policy_generation: u64, pub minimum_revision: u64 }

/// An already-authenticated claim lease. Construction belongs at the trusted
/// center/verifier seam, never at a raw request-body deserialization seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp<'a> {
    pub authority: Authority,
    pub issuer: &'a str,
    pub policy_generation: u64,
    pub evidence_revision: u64,
    pub issued_at: u64,
    pub valid_until: u64,
    pub revocation: Revocation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeIdentity<'a> {
    pub tenant_id: &'a str,
    pub device_id: &'a str,
    pub machine_id: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoleBinding<'a> {
    pub subject: NodeIdentity<'a>,
    pub role: DeviceRole,
    pub stamp: Stamp<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpPrefix { network: IpAddr, length: u8 }

impl IpPrefix {
    /// Exact canonical prefix only: reject host bits, zero-length default
    /// routes and IPv4-mapped-IPv6 prefixes. A /0 is not one geographic site.
    pub fn new(network: IpAddr, length: u8) -> Option<Self> {
        match network {
            IpAddr::V4(ip) if (1..=32).contains(&length) => {
                let mask = u32::MAX << (32 - length);
                (u32::from(ip) & mask == u32::from(ip)).then_some(Self { network, length })
            }
            IpAddr::V6(ip) if (1..=128).contains(&length) && ip.to_ipv4_mapped().is_none() => {
                let mask = u128::MAX << (128 - length);
                (u128::from(ip) & mask == u128::from(ip)).then_some(Self { network, length })
            }
            _ => None,
        }
    }

    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, canonical_ip(address)) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX << (32 - self.length);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX << (128 - self.length);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }

    pub fn network(self) -> IpAddr { self.network }
    pub fn length(self) -> u8 { self.length }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource<'a> {
    Node(NodeIdentity<'a>),
    /// Scoped attachment evidence, not a CIDR or gateway-location inference.
    /// Multi-region networks must have separate approved regional resources.
    NetworkAttachment {
        tenant_id: &'a str,
        site_id: &'a str,
        attachment_id: &'a str,
        gateway: NodeIdentity<'a>,
        prefix: IpPrefix,
    },
    /// The actual address selected by the dialer, not the original DNS label.
    PublicAddress(IpAddr),
    UnboundAddress(IpAddr),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZoneEvidence<'a> {
    pub subject: Resource<'a>,
    pub zone: Option<Zone>,
    /// GeoIP dataset or approved attachment-evidence revision; not a label.
    pub classifier_revision: &'a str,
    pub stamp: Stamp<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin<'a> {
    pub identity: NodeIdentity<'a>,
    pub role: RoleBinding<'a>,
    pub zone: Option<ZoneEvidence<'a>>,
}

/// Current authenticated association of a node identity to one selected
/// address. A node-zone assertion is not an endpoint/address assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeAddressBinding<'a> {
    pub subject: NodeIdentity<'a>,
    pub address: IpAddr,
    pub stamp: Stamp<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint<'a> {
    pub resource: Resource<'a>,
    /// Required for every admission, including nodes and intermediate hops.
    /// Logical/address-free discovery must not return a dial-capable allow.
    pub dialed_address: Option<IpAddr>,
    pub zone: Option<ZoneEvidence<'a>>,
    /// Mandatory for Resource::Node, bound to this exact selected address.
    pub node_address_binding: Option<NodeAddressBinding<'a>>,
    /// Additional actual-IP classification for a client-constrained node or
    /// attachment outside the explicit scoped-private ranges. Server-origin
    /// infrastructure does not require GeoIP to obtain address-authenticated
    /// admission. Private/overlay addresses cannot reuse it as a shortcut.
    /// Resource::PublicAddress instead uses `zone` for this exact-IP evidence.
    pub public_address_zone: Option<ZoneEvidence<'a>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathCompleteness { Complete, Incomplete }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlannedPath<'a> {
    /// Original authenticated principal, never replaced by the current relay.
    pub origin: NodeIdentity<'a>,
    pub hops: &'a [Endpoint<'a>],
    pub completeness: PathCompleteness,
    pub stamp: Stamp<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationKind { TenantGrant, ShareGrant, Denied, Unavailable }

/// Existing tenant/share/ACL authorization is a separate, exact-pair decision.
/// Cross-tenant sharing is valid if that existing authenticated decision permits
/// it; this regional module does not silently outlaw legitimate sharing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExistingAuthorization<'a> {
    pub origin: NodeIdentity<'a>,
    pub destination: Resource<'a>,
    pub kind: AuthorizationKind,
    pub stamp: Stamp<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrdinaryAclMode { Off, Warn, Enforce }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BusinessRequest<'a> {
    pub origin: Origin<'a>,
    pub destination: Endpoint<'a>,
    pub path: PlannedPath<'a>,
    pub authorization: ExistingAuthorization<'a>,
    /// Observability only: Off/Warn never bypass the hard regional gate.
    /// The existing authorization seam computes its own effective ACL result.
    pub ordinary_acl_mode: OrdinaryAclMode,
}

/// Parts from the HTTP/WebSocket dialer's parsed URL. This module does not
/// parse raw URLs or guess a host by splitting userinfo/slashes itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParsedControlTarget<'a> {
    pub scheme: &'a str,
    pub host: &'a str,
    pub effective_port: u16,
    pub userinfo_present: bool,
    pub fragment_present: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsPeer<'a> { VerifiedHostname(&'a str), Unverified }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementOperation {
    Bootstrap, Registration, Login, Configuration, Policy, Heartbeat, Health,
    ForwardControl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteAuthority { RegisteredRouter, UntrustedClaim }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisteredControlRoute<'a> {
    /// Actual router registration key, not a path prefix invented here.
    /// The caller must have matched method/path/body to this exact operation.
    pub route_key: &'a str,
    pub operation: ManagementOperation,
    pub authority: RouteAuthority,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageClass { Control, Business }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationGate { Allowed, Denied, Unavailable }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirectEvidence { None, VerifiedSameOrigin, UnverifiedOrCrossOrigin }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagementChannel<'a> {
    pub target: ParsedControlTarget<'a>,
    pub tls_peer: TlsPeer<'a>,
    pub route: RegisteredControlRoute<'a>,
    pub message_class: MessageClass,
    /// Login/bootstrap can have an allowed public endpoint gate without an
    /// enrolled device. This never grants logged-in administrative powers.
    pub application_gate: ApplicationGate,
    pub redirect: RedirectEvidence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> { Business(BusinessRequest<'a>), Management(ManagementChannel<'a>) }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckScope { Origin, Destination, Hop(usize), Path, Authorization, Management }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenialReason {
    InvalidIdentity, UntrustedEvidence, InvalidEvidence, StaleGeneration,
    StaleRevision, FutureEvidence, ExpiredEvidence, RevokedEvidence,
    UnknownRole, SubjectMismatch, UnknownZone, CrossRegion, UnboundDestination,
    MissingAddress, MissingAddressBinding, PublicAddressEvidenceRequired,
    AddressMismatch, PrefixMismatch, MissingGateway, IncompletePath, TooManyHops,
    AuthorizationDenied, AuthorizationUnavailable, InvalidManagementTarget,
    UnverifiedTls, UnregisteredControlRoute, BusinessMessage, ApplicationDenied,
    UnsafeRedirect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    AllowBusiness,
    AllowManagement,
    Deny { reason: DenialReason, scope: CheckScope },
}

pub struct BusinessReachability;

impl BusinessReachability {
    pub fn decide(context: Context, request: Request<'_>) -> Decision {
        let result = match request {
            Request::Management(channel) => management(channel).map(|_| Decision::AllowManagement),
            Request::Business(request) => business(context, request).map(|_| Decision::AllowBusiness),
        };
        result.unwrap_or_else(|(reason, scope)| Decision::Deny { reason, scope })
    }
}

type Denied = (DenialReason, CheckScope);

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 256 && !id.chars().any(|c| c.is_control() || c.is_whitespace())
}

fn valid_identity(identity: NodeIdentity<'_>) -> bool {
    valid_id(identity.tenant_id) && valid_id(identity.device_id) && valid_id(identity.machine_id)
}

fn stamp(context: Context, evidence: Stamp<'_>, scope: CheckScope) -> Result<(), Denied> {
    let reason = if evidence.authority != Authority::CenterAuthenticated {
        Some(DenialReason::UntrustedEvidence)
    } else if !valid_id(evidence.issuer) || evidence.valid_until <= evidence.issued_at {
        Some(DenialReason::InvalidEvidence)
    } else if evidence.policy_generation != context.policy_generation {
        Some(DenialReason::StaleGeneration)
    } else if evidence.evidence_revision < context.minimum_revision {
        Some(DenialReason::StaleRevision)
    } else if evidence.revocation != Revocation::Active {
        Some(DenialReason::RevokedEvidence)
    } else if evidence.issued_at > context.now {
        Some(DenialReason::FutureEvidence)
    } else if evidence.valid_until <= context.now {
        Some(DenialReason::ExpiredEvidence)
    } else { None };
    match reason { Some(r) => Err((r, scope)), None => Ok(()) }
}

fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
        _ => address,
    }
}

fn same_resource(a: Resource<'_>, b: Resource<'_>) -> bool {
    match (a, b) {
        (Resource::PublicAddress(a), Resource::PublicAddress(b)) => canonical_ip(a) == canonical_ip(b),
        _ => a == b,
    }
}

/// Positive classification only. Absence from this small explicit set does NOT
/// mean an address is globally reachable or safely local; it means a restricted
/// client needs independent actual-IP evidence. In particular IANA192.0.0.9/.10
/// are globally reachable exceptions within192.0.0.0/24, not private addresses.
fn scoped_private(address: IpAddr) -> bool {
    match canonical_ip(address) {
        IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            a == 10 || (a == 100 && (64..=127).contains(&b))
                || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            (s[0] & 0xfe00) == 0xfc00
        }
    }
}

fn endpoint(context: Context, endpoint: Endpoint<'_>, scope: CheckScope, client_constrained: bool) -> Result<Option<Zone>, Denied> {
    let address = endpoint.dialed_address.ok_or((DenialReason::MissingAddress, scope))?;
    match endpoint.resource {
        Resource::Node(identity) => {
            if !valid_identity(identity) { return Err((DenialReason::InvalidIdentity, scope)); }
            let binding = endpoint.node_address_binding.ok_or((DenialReason::MissingAddressBinding, scope))?;
            stamp(context, binding.stamp, scope)?;
            if binding.subject != identity { return Err((DenialReason::SubjectMismatch, scope)); }
            if canonical_ip(binding.address) != canonical_ip(address) { return Err((DenialReason::AddressMismatch, scope)); }
        }
        Resource::NetworkAttachment { tenant_id, site_id, attachment_id, gateway, prefix } => {
            if !valid_id(tenant_id) || !valid_id(site_id) || !valid_id(attachment_id) || !valid_identity(gateway) || tenant_id != gateway.tenant_id {
                return Err((DenialReason::InvalidIdentity, scope));
            }
            if endpoint.node_address_binding.is_some() { return Err((DenialReason::InvalidEvidence, scope)); }
            if !prefix.contains(address) {
                return Err((DenialReason::PrefixMismatch, scope));
            }
        }
        Resource::PublicAddress(expected) => {
            if scoped_private(expected) { return Err((DenialReason::UnboundDestination, scope)); }
            if canonical_ip(address) != canonical_ip(expected) {
                return Err((DenialReason::AddressMismatch, scope));
            }
            if endpoint.node_address_binding.is_some() || endpoint.public_address_zone.is_some() { return Err((DenialReason::InvalidEvidence, scope)); }
            return Ok(None);
        }
        Resource::UnboundAddress(_) => return Err((DenialReason::UnboundDestination, scope)),
    }
    // This boolean is derived only AFTER the original role's authenticated
    // binding has been validated below; it is not a client-supplied escape.
    if !client_constrained {
        Ok(None)
    } else if !scoped_private(address) {
        let evidence = endpoint.public_address_zone.ok_or((DenialReason::PublicAddressEvidenceRequired, scope))?;
        zone(context, Resource::PublicAddress(canonical_ip(address)), Some(evidence), scope).map(Some)
    } else if endpoint.public_address_zone.is_some() {
        Err((DenialReason::InvalidEvidence, scope))
    } else {
        Ok(None)
    }
}

fn checked_zone_evidence<'a>(context: Context, expected: Resource<'a>, evidence: Option<ZoneEvidence<'a>>, scope: CheckScope) -> Result<ZoneEvidence<'a>, Denied> {
    let evidence = evidence.ok_or((DenialReason::UnknownZone, scope))?;
    stamp(context, evidence.stamp, scope)?;
    if !same_resource(evidence.subject, expected) { return Err((DenialReason::SubjectMismatch, scope)); }
    if !valid_id(evidence.classifier_revision) { return Err((DenialReason::InvalidEvidence, scope)); }
    Ok(evidence)
}

fn zone(context: Context, expected: Resource<'_>, evidence: Option<ZoneEvidence<'_>>, scope: CheckScope) -> Result<Zone, Denied> {
    checked_zone_evidence(context, expected, evidence, scope)?.zone.ok_or((DenialReason::UnknownZone, scope))
}

fn business(context: Context, request: BusinessRequest<'_>) -> Result<(), Denied> {
    let origin = request.origin;
    if !valid_identity(origin.identity) { return Err((DenialReason::InvalidIdentity, CheckScope::Origin)); }
    stamp(context, origin.role.stamp, CheckScope::Origin)?;
    if origin.role.subject != origin.identity { return Err((DenialReason::SubjectMismatch, CheckScope::Origin)); }
    if origin.role.role == DeviceRole::Unknown { return Err((DenialReason::UnknownRole, CheckScope::Origin)); }
    let client_constrained = origin.role.role == DeviceRole::Client;
    let destination_public_zone = endpoint(context, request.destination, CheckScope::Destination, client_constrained)?;
    stamp(context, request.path.stamp, CheckScope::Path)?;
    if request.path.origin != origin.identity { return Err((DenialReason::SubjectMismatch, CheckScope::Path)); }
    if request.path.completeness != PathCompleteness::Complete { return Err((DenialReason::IncompletePath, CheckScope::Path)); }
    if request.path.hops.len() > MAX_MANAGED_HOPS { return Err((DenialReason::TooManyHops, CheckScope::Path)); }
    for (index, hop) in request.path.hops.iter().enumerate() {
        endpoint(context, *hop, CheckScope::Hop(index), client_constrained)?;
        if !matches!(hop.resource, Resource::Node(_)) { return Err((DenialReason::InvalidIdentity, CheckScope::Hop(index))); }
    }
    if let Resource::NetworkAttachment { gateway, .. } = request.destination.resource {
        if !request.path.hops.iter().any(|hop| hop.resource == Resource::Node(gateway)) {
            return Err((DenialReason::MissingGateway, CheckScope::Path));
        }
        // Attachment authority is required even for unrestricted server-origin
        // infrastructure. It may not inherit a gateway's geographic label.
        checked_zone_evidence(context, request.destination.resource, request.destination.zone, CheckScope::Destination)?;
    }
    if client_constrained {
        let origin_zone = zone(context, Resource::Node(origin.identity), origin.zone, CheckScope::Origin)?;
        if zone(context, request.destination.resource, request.destination.zone, CheckScope::Destination)? != origin_zone {
            return Err((DenialReason::CrossRegion, CheckScope::Destination));
        }
        if destination_public_zone.is_some_and(|z| z != origin_zone) {
            return Err((DenialReason::CrossRegion, CheckScope::Destination));
        }
        for (index, hop) in request.path.hops.iter().enumerate() {
            if zone(context, hop.resource, hop.zone, CheckScope::Hop(index))? != origin_zone {
                return Err((DenialReason::CrossRegion, CheckScope::Hop(index)));
            }
            if endpoint(context, *hop, CheckScope::Hop(index), true)?.is_some_and(|z| z != origin_zone) {
                return Err((DenialReason::CrossRegion, CheckScope::Hop(index)));
            }
        }
    }
    let authorization = request.authorization;
    stamp(context, authorization.stamp, CheckScope::Authorization)?;
    if authorization.origin != origin.identity || !same_resource(authorization.destination, request.destination.resource) {
        return Err((DenialReason::SubjectMismatch, CheckScope::Authorization));
    }
    match authorization.kind {
        AuthorizationKind::TenantGrant | AuthorizationKind::ShareGrant => Ok(()),
        AuthorizationKind::Denied => Err((DenialReason::AuthorizationDenied, CheckScope::Authorization)),
        AuthorizationKind::Unavailable => Err((DenialReason::AuthorizationUnavailable, CheckScope::Authorization)),
    }
}

fn management(channel: ManagementChannel<'_>) -> Result<(), Denied> {
    let scope = CheckScope::Management;
    let target = channel.target;
    if !matches!(target.scheme, "https" | "wss") || !target.host.eq_ignore_ascii_case(MANAGEMENT_HOST)
        || target.effective_port != 443 || target.userinfo_present || target.fragment_present {
        return Err((DenialReason::InvalidManagementTarget, scope));
    }
    if !matches!(channel.tls_peer, TlsPeer::VerifiedHostname(host) if host.eq_ignore_ascii_case(MANAGEMENT_HOST)) {
        return Err((DenialReason::UnverifiedTls, scope));
    }
    if channel.route.authority != RouteAuthority::RegisteredRouter || !valid_id(channel.route.route_key) {
        return Err((DenialReason::UnregisteredControlRoute, scope));
    }
    if channel.message_class != MessageClass::Control { return Err((DenialReason::BusinessMessage, scope)); }
    if channel.application_gate != ApplicationGate::Allowed { return Err((DenialReason::ApplicationDenied, scope)); }
    if channel.redirect == RedirectEvidence::UnverifiedOrCrossOrigin { return Err((DenialReason::UnsafeRedirect, scope)); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(raw: &str) -> IpAddr { raw.parse().unwrap() }
    const CTX: Context = Context { now: 100, policy_generation: 7, minimum_revision: 3 };
    const A: NodeIdentity<'static> = NodeIdentity { tenant_id: "tenant-a", device_id: "client-a", machine_id: "machine-a" };
    const B: NodeIdentity<'static> = NodeIdentity { tenant_id: "tenant-a", device_id: "server-b", machine_id: "machine-b" };
    const C: NodeIdentity<'static> = NodeIdentity { tenant_id: "tenant-b", device_id: "server-c", machine_id: "machine-c" };
    fn lease() -> Stamp<'static> { Stamp { authority: Authority::CenterAuthenticated, issuer: "center-1", policy_generation: 7, evidence_revision: 4, issued_at: 90, valid_until: 110, revocation: Revocation::Active } }
    fn evidence(resource: Resource<'static>, zone: Zone) -> ZoneEvidence<'static> { ZoneEvidence { subject: resource, zone: Some(zone), classifier_revision: "dataset-or-attachment-4", stamp: lease() } }
    fn node(identity: NodeIdentity<'static>, region: Zone) -> Endpoint<'static> { Endpoint { resource: Resource::Node(identity), dialed_address: Some(ip("100.64.0.2")), zone: Some(evidence(Resource::Node(identity), region)), node_address_binding: Some(NodeAddressBinding { subject: identity, address: ip("100.64.0.2"), stamp: lease() }), public_address_zone: None } }
    fn request(zone: Zone, destination: Endpoint<'static>) -> BusinessRequest<'static> {
        BusinessRequest {
            origin: Origin { identity: A, role: RoleBinding { subject: A, role: DeviceRole::Client, stamp: lease() }, zone: Some(evidence(Resource::Node(A), zone)) },
            destination,
            path: PlannedPath { origin: A, hops: &[], completeness: PathCompleteness::Complete, stamp: lease() },
            authorization: ExistingAuthorization { origin: A, destination: destination.resource, kind: AuthorizationKind::TenantGrant, stamp: lease() },
            ordinary_acl_mode: OrdinaryAclMode::Enforce,
        }
    }
    fn decide(request: BusinessRequest<'_>) -> Decision { BusinessReachability::decide(CTX, Request::Business(request)) }
    fn denied(request: BusinessRequest<'_>, reason: DenialReason, scope: CheckScope) { assert_eq!(decide(request), Decision::Deny { reason, scope }); }
    fn control() -> ManagementChannel<'static> {
        ManagementChannel {
            target: ParsedControlTarget { scheme: "https", host: MANAGEMENT_HOST, effective_port: 443, userinfo_present: false, fragment_present: false },
            tls_peer: TlsPeer::VerifiedHostname(MANAGEMENT_HOST),
            route: RegisteredControlRoute { route_key: "actual-router-registration", operation: ManagementOperation::Login, authority: RouteAuthority::RegisteredRouter },
            message_class: MessageClass::Control, application_gate: ApplicationGate::Allowed, redirect: RedirectEvidence::None,
        }
    }
    fn management_decision(c: ManagementChannel<'_>) -> Decision { BusinessReachability::decide(CTX, Request::Management(c)) }
    fn management_denied(c: ManagementChannel<'_>, reason: DenialReason) { assert_eq!(management_decision(c), Decision::Deny { reason, scope: CheckScope::Management }); }
    fn attachment(site: &'static str, zone: Zone) -> Endpoint<'static> {
        let resource = Resource::NetworkAttachment { tenant_id: "tenant-a", site_id: site, attachment_id: "attachment-1", gateway: B, prefix: IpPrefix::new(ip("10.1.0.0"), 16).unwrap() };
        Endpoint { resource, dialed_address: Some(ip("10.1.2.3")), zone: Some(evidence(resource, zone)), node_address_binding: None, public_address_zone: None }
    }

    fn reject_node_in_destination_and_hop(bad: Endpoint<'static>, reason: DenialReason) {
        denied(request(Zone::Mainland, bad), reason, CheckScope::Destination);
        let hops = [bad];
        let mut r = request(Zone::Mainland, node(B, Zone::Mainland));
        r.path.hops = &hops;
        denied(r, reason, CheckScope::Hop(0));
    }

    fn public_node(address: &str, public_zone: Option<Zone>) -> Endpoint<'static> {
        let address = ip(address);
        let mut endpoint = node(B, Zone::Mainland);
        endpoint.dialed_address = Some(address);
        endpoint.node_address_binding.as_mut().unwrap().address = address;
        endpoint.public_address_zone = public_zone.map(|z| evidence(Resource::PublicAddress(canonical_ip(address)), z));
        endpoint
    }

    fn public_attachment(address: &str) -> Endpoint<'static> {
        let address = ip(address);
        let prefix = match canonical_ip(address) {
            IpAddr::V4(_) => IpPrefix::new(ip("8.8.8.0"), 24).unwrap(),
            IpAddr::V6(_) => IpPrefix::new(ip("2606:4700::"), 32).unwrap(),
        };
        let resource = Resource::NetworkAttachment { tenant_id: "tenant-a", site_id: "approved-site", attachment_id: "public-site", gateway: B, prefix };
        Endpoint { resource, dialed_address: Some(address), zone: Some(evidence(resource, Zone::Mainland)), node_address_binding: None, public_address_zone: None }
    }

    #[test]
    fn node_destination_and_hop_require_a_selected_address() {
        let mut bad = node(B, Zone::Mainland);
        bad.dialed_address = None;
        reject_node_in_destination_and_hop(bad, DenialReason::MissingAddress);
    }

    #[test]
    fn node_destination_and_hop_require_current_authenticated_address_binding() {
        let mut bad = node(B, Zone::Mainland);
        bad.node_address_binding = None;
        reject_node_in_destination_and_hop(bad, DenialReason::MissingAddressBinding);
        bad = node(B, Zone::Mainland);
        bad.node_address_binding.as_mut().unwrap().stamp.authority = Authority::UntrustedReport;
        reject_node_in_destination_and_hop(bad, DenialReason::UntrustedEvidence);
        bad.node_address_binding.as_mut().unwrap().stamp = lease();
        bad.node_address_binding.as_mut().unwrap().stamp.policy_generation = 6;
        reject_node_in_destination_and_hop(bad, DenialReason::StaleGeneration);
        bad.node_address_binding.as_mut().unwrap().stamp = lease();
        bad.node_address_binding.as_mut().unwrap().stamp.valid_until = CTX.now;
        reject_node_in_destination_and_hop(bad, DenialReason::ExpiredEvidence);
        bad.node_address_binding.as_mut().unwrap().stamp = lease();
        bad.node_address_binding.as_mut().unwrap().stamp.revocation = Revocation::Revoked;
        reject_node_in_destination_and_hop(bad, DenialReason::RevokedEvidence);
    }

    #[test]
    fn node_destination_and_hop_reject_substituted_ipv4_ipv6_and_mapped_addresses() {
        for address in ["8.8.8.8", "::ffff:8.8.8.8", "2606:4700:4700::1111", "10.99.0.3"] {
            let mut bad = node(B, Zone::Mainland);
            bad.dialed_address = Some(ip(address));
            reject_node_in_destination_and_hop(bad, DenialReason::AddressMismatch);
        }
        let mut changed_a = public_node("8.8.8.8", Some(Zone::Mainland));
        changed_a.dialed_address = Some(ip("1.1.1.1"));
        reject_node_in_destination_and_hop(changed_a, DenialReason::AddressMismatch);
        let mut changed_aaaa = public_node("2606:4700:4700::1111", Some(Zone::Mainland));
        changed_aaaa.dialed_address = Some(ip("2606:4700:4700::1001"));
        reject_node_in_destination_and_hop(changed_aaaa, DenialReason::AddressMismatch);
    }

    #[test]
    fn node_address_binding_cannot_be_reused_for_another_machine_or_tenant() {
        let mut bad = node(B, Zone::Mainland);
        bad.node_address_binding.as_mut().unwrap().subject.machine_id = "other-machine";
        reject_node_in_destination_and_hop(bad, DenialReason::SubjectMismatch);
        bad = node(B, Zone::Mainland);
        bad.node_address_binding.as_mut().unwrap().subject.tenant_id = "other-tenant";
        reject_node_in_destination_and_hop(bad, DenialReason::SubjectMismatch);
    }

    #[test]
    fn node_public_addresses_need_independent_actual_ip_classification() {
        for address in ["8.8.8.8", "::ffff:8.8.8.8", "2606:4700:4700::1111"] {
            reject_node_in_destination_and_hop(public_node(address, None), DenialReason::PublicAddressEvidenceRequired);
            reject_node_in_destination_and_hop(public_node(address, Some(Zone::NonMainland)), DenialReason::CrossRegion);
            // Synthetic trusted classification, not a claim these real IPs are CN.
            assert_eq!(decide(request(Zone::Mainland, public_node(address, Some(Zone::Mainland)))), Decision::AllowBusiness);
        }
    }

    #[test]
    fn node_public_evidence_must_match_actual_address_and_be_current() {
        let mut bad = public_node("8.8.8.8", Some(Zone::Mainland));
        bad.public_address_zone.as_mut().unwrap().subject = Resource::PublicAddress(ip("1.1.1.1"));
        reject_node_in_destination_and_hop(bad, DenialReason::SubjectMismatch);
        bad = public_node("8.8.8.8", Some(Zone::Mainland));
        bad.public_address_zone.as_mut().unwrap().stamp.valid_until = CTX.now;
        reject_node_in_destination_and_hop(bad, DenialReason::ExpiredEvidence);
    }

    #[test]
    fn public_attachment_ipv4_ipv6_and_mapped_addresses_cannot_relabel_region() {
        let hops = [node(B, Zone::Mainland)];
        for address in ["8.8.8.8", "::ffff:8.8.8.8", "2606:4700:4700::1111"] {
            let mut endpoint = public_attachment(address);
            let mut r = request(Zone::Mainland, endpoint);
            r.path.hops = &hops;
            denied(r, DenialReason::PublicAddressEvidenceRequired, CheckScope::Destination);
            endpoint.public_address_zone = Some(evidence(Resource::PublicAddress(canonical_ip(ip(address))), Zone::NonMainland));
            r.destination = endpoint;
            denied(r, DenialReason::CrossRegion, CheckScope::Destination);
            endpoint.public_address_zone.as_mut().unwrap().zone = Some(Zone::Mainland);
            r.destination = endpoint;
            assert_eq!(decide(r), Decision::AllowBusiness);
        }
    }

    #[test]
    fn public_attachment_cannot_reuse_stale_or_other_address_proof() {
        let hops = [node(B, Zone::Mainland)];
        let mut endpoint = public_attachment("8.8.8.8");
        endpoint.public_address_zone = Some(evidence(Resource::PublicAddress(ip("1.1.1.1")), Zone::Mainland));
        let mut r = request(Zone::Mainland, endpoint);
        r.path.hops = &hops;
        denied(r, DenialReason::SubjectMismatch, CheckScope::Destination);
        endpoint.public_address_zone = Some(evidence(Resource::PublicAddress(ip("8.8.8.8")), Zone::Mainland));
        endpoint.public_address_zone.as_mut().unwrap().stamp.valid_until = CTX.now;
        r.destination = endpoint;
        denied(r, DenialReason::ExpiredEvidence, CheckScope::Destination);
    }

    #[test]
    fn authentic_private_overlay_and_canonical_mapped_private_node_still_work() {
        for address in ["100.64.0.2", "10.1.2.3", "fd12:3456::123", "::ffff:100.64.0.2"] {
            let mut endpoint = node(B, Zone::Mainland);
            endpoint.dialed_address = Some(ip(address));
            endpoint.node_address_binding.as_mut().unwrap().address = canonical_ip(ip(address));
            assert_eq!(decide(request(Zone::Mainland, endpoint)), Decision::AllowBusiness);
            let hops = [endpoint];
            let mut r = request(Zone::Mainland, node(B, Zone::Mainland));
            r.path.hops = &hops;
            assert_eq!(decide(r), Decision::AllowBusiness);
        }
    }

    #[test]
    fn server_origin_keeps_cross_region_rights_but_not_address_free_admission() {
        let mut r = request(Zone::Mainland, public_node("8.8.8.8", Some(Zone::NonMainland)));
        r.origin.role.role = DeviceRole::Server;
        r.origin.zone = None;
        assert_eq!(decide(r), Decision::AllowBusiness);
        r.destination.dialed_address = None;
        denied(r, DenialReason::MissingAddress, CheckScope::Destination);
        r.destination = node(B, Zone::NonMainland);
        r.destination.zone = None;
        assert_eq!(decide(r), Decision::AllowBusiness);
    }

    #[test]
    fn iana_public_exceptions_need_actual_ip_evidence_for_node_destinations_and_hops() {
        for address in ["192.0.0.9", "192.0.0.10", "::ffff:192.0.0.9", "::ffff:192.0.0.10"] {
            reject_node_in_destination_and_hop(public_node(address, None), DenialReason::PublicAddressEvidenceRequired);
            reject_node_in_destination_and_hop(public_node(address, Some(Zone::NonMainland)), DenialReason::CrossRegion);
            // Synthetic center classifications exercise the decision matrix;
            // these assertions are not real GeoIP claims about IANA anycast.
            let endpoint = public_node(address, Some(Zone::Mainland));
            assert_eq!(decide(request(Zone::Mainland, endpoint)), Decision::AllowBusiness);
            let hops = [endpoint];
            let mut r = request(Zone::Mainland, node(B, Zone::Mainland));
            r.path.hops = &hops;
            assert_eq!(decide(r), Decision::AllowBusiness);
        }
    }

    #[test]
    fn iana_public_exceptions_cannot_inherit_attachment_zone() {
        let hops = [node(B, Zone::Mainland)];
        for address in ["192.0.0.9", "192.0.0.10", "::ffff:192.0.0.9", "::ffff:192.0.0.10"] {
            let address = ip(address);
            let resource = Resource::NetworkAttachment {
                tenant_id: "tenant-a", site_id: "site-iana-test", attachment_id: "iana-test",
                gateway: B, prefix: IpPrefix::new(ip("192.0.0.0"), 24).unwrap(),
            };
            let mut endpoint = Endpoint { resource, dialed_address: Some(address), zone: Some(evidence(resource, Zone::Mainland)), node_address_binding: None, public_address_zone: None };
            let mut r = request(Zone::Mainland, endpoint);
            r.path.hops = &hops;
            denied(r, DenialReason::PublicAddressEvidenceRequired, CheckScope::Destination);
            endpoint.public_address_zone = Some(evidence(Resource::PublicAddress(canonical_ip(address)), Zone::NonMainland));
            r.destination = endpoint;
            denied(r, DenialReason::CrossRegion, CheckScope::Destination);
            endpoint.public_address_zone.as_mut().unwrap().zone = Some(Zone::Mainland);
            r.destination = endpoint;
            assert_eq!(decide(r), Decision::AllowBusiness);
        }
    }

    #[test]
    fn iana_public_exceptions_are_consistent_for_direct_public_address_resources() {
        for address in ["192.0.0.9", "192.0.0.10", "::ffff:192.0.0.9", "::ffff:192.0.0.10"] {
            let address = ip(address);
            let resource = Resource::PublicAddress(canonical_ip(address));
            let mut endpoint = Endpoint { resource, dialed_address: Some(address), zone: None, node_address_binding: None, public_address_zone: None };
            denied(request(Zone::Mainland, endpoint), DenialReason::UnknownZone, CheckScope::Destination);
            endpoint.zone = Some(evidence(resource, Zone::NonMainland));
            denied(request(Zone::Mainland, endpoint), DenialReason::CrossRegion, CheckScope::Destination);
            endpoint.zone.as_mut().unwrap().zone = Some(Zone::Mainland);
            assert_eq!(decide(request(Zone::Mainland, endpoint)), Decision::AllowBusiness);
        }
    }

    #[test]
    fn only_explicit_scoped_private_ranges_skip_independent_actual_ip_classification() {
        for address in ["10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.1", "100.64.0.1", "100.127.255.254", "fd12:3456::1", "fc00::1", "::ffff:10.1.2.3"] {
            assert!(scoped_private(ip(address)), "{address}");
        }
        for address in ["192.0.0.8", "192.0.0.9", "192.0.0.10", "169.254.1.1", "127.0.0.1", "198.18.0.1", "203.0.113.1", "fe80::1", "2001:db8::1", "100.63.255.255", "100.128.0.1", "::ffff:192.0.0.9"] {
            assert!(!scoped_private(ip(address)), "{address}");
            reject_node_in_destination_and_hop(public_node(address, None), DenialReason::PublicAddressEvidenceRequired);
        }
    }

    #[test]
    fn server_public_node_and_hop_admission_needs_address_authentication_not_geoip() {
        let public = public_node("192.0.0.9", None);
        reject_node_in_destination_and_hop(public, DenialReason::PublicAddressEvidenceRequired);
        let mut r = request(Zone::Mainland, public);
        r.origin.role.role = DeviceRole::Server;
        r.origin.zone = None;
        r.destination.zone = None;
        assert_eq!(decide(r), Decision::AllowBusiness);
        r.authorization.kind = AuthorizationKind::Denied;
        denied(r, DenialReason::AuthorizationDenied, CheckScope::Authorization);
        r.authorization.kind = AuthorizationKind::TenantGrant;
        r.destination.node_address_binding.as_mut().unwrap().stamp.valid_until = CTX.now;
        denied(r, DenialReason::ExpiredEvidence, CheckScope::Destination);
        let hops = [public];
        let mut via = request(Zone::Mainland, node(B, Zone::NonMainland));
        via.origin.role.role = DeviceRole::Server;
        via.origin.zone = None;
        via.destination.zone = None;
        via.path.hops = &hops;
        assert_eq!(decide(via), Decision::AllowBusiness);
        via.authorization.kind = AuthorizationKind::Denied;
        denied(via, DenialReason::AuthorizationDenied, CheckScope::Authorization);
    }

    #[test]
    fn server_attachment_requires_scope_authority_but_not_a_client_geoip_partition() {
        let hops = [node(B, Zone::Mainland)];
        let mut endpoint = attachment("site-cn", Zone::Mainland);
        endpoint.zone.as_mut().unwrap().zone = None;
        let mut r = request(Zone::Mainland, endpoint);
        r.path.hops = &hops;
        denied(r, DenialReason::UnknownZone, CheckScope::Destination);
        r.origin.role.role = DeviceRole::Server;
        r.origin.zone = None;
        assert_eq!(decide(r), Decision::AllowBusiness);
        r.destination.zone.as_mut().unwrap().stamp.authority = Authority::UntrustedReport;
        denied(r, DenialReason::UntrustedEvidence, CheckScope::Destination);
    }

    #[test] fn mainland_same_zone_requires_and_receives_authorization() { assert_eq!(decide(request(Zone::Mainland, node(B, Zone::Mainland))), Decision::AllowBusiness); }
    #[test] fn nonmainland_same_zone_is_allowed() { assert_eq!(decide(request(Zone::NonMainland, node(B, Zone::NonMainland))), Decision::AllowBusiness); }
    #[test] fn both_cross_zone_directions_are_denied() {
        denied(request(Zone::Mainland, node(B, Zone::NonMainland)), DenialReason::CrossRegion, CheckScope::Destination);
        denied(request(Zone::NonMainland, node(B, Zone::Mainland)), DenialReason::CrossRegion, CheckScope::Destination);
    }
    #[test] fn off_and_warn_do_not_disable_region_gate() {
        for mode in [OrdinaryAclMode::Off, OrdinaryAclMode::Warn, OrdinaryAclMode::Enforce] {
            let mut r = request(Zone::Mainland, node(B, Zone::NonMainland)); r.ordinary_acl_mode = mode;
            denied(r, DenialReason::CrossRegion, CheckScope::Destination);
        }
    }
    #[test] fn unknown_origin_zone_is_not_nonmainland() { let mut r = request(Zone::NonMainland, node(B, Zone::NonMainland)); r.origin.zone = None; denied(r, DenialReason::UnknownZone, CheckScope::Origin); }
    #[test] fn explicit_unknown_destination_zone_is_denied() { let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.destination.zone.as_mut().unwrap().zone = None; denied(r, DenialReason::UnknownZone, CheckScope::Destination); }
    #[test] fn reported_role_cannot_become_server_bypass() { let mut r = request(Zone::Mainland, node(B, Zone::NonMainland)); r.origin.role.role = DeviceRole::Server; r.origin.role.stamp.authority = Authority::UntrustedReport; denied(r, DenialReason::UntrustedEvidence, CheckScope::Origin); }
    #[test] fn unknown_role_is_denied() { let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.origin.role.role = DeviceRole::Unknown; denied(r, DenialReason::UnknownRole, CheckScope::Origin); }
    #[test] fn role_binding_must_match_machine_and_device() { let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.origin.role.subject.machine_id = "replacement"; denied(r, DenialReason::SubjectMismatch, CheckScope::Origin); }
    #[test] fn zone_binding_must_match_subject_not_a_peer_label() { let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.origin.zone.as_mut().unwrap().subject = Resource::Node(B); denied(r, DenialReason::SubjectMismatch, CheckScope::Origin); }
    #[test] fn expired_zone_is_denied_at_exact_boundary() { let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.destination.zone.as_mut().unwrap().stamp.valid_until = CTX.now; denied(r, DenialReason::ExpiredEvidence, CheckScope::Destination); }
    #[test] fn old_generation_and_revision_are_denied() {
        let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.origin.zone.as_mut().unwrap().stamp.policy_generation = 6; denied(r, DenialReason::StaleGeneration, CheckScope::Origin);
        r.origin.zone.as_mut().unwrap().stamp = lease(); r.origin.zone.as_mut().unwrap().stamp.evidence_revision = 2; denied(r, DenialReason::StaleRevision, CheckScope::Origin);
    }
    #[test] fn future_and_revoked_evidence_are_denied() {
        let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.origin.zone.as_mut().unwrap().stamp.issued_at = 101; denied(r, DenialReason::FutureEvidence, CheckScope::Origin);
        r.origin.zone.as_mut().unwrap().stamp = lease(); r.origin.zone.as_mut().unwrap().stamp.revocation = Revocation::Revoked; denied(r, DenialReason::RevokedEvidence, CheckScope::Origin);
    }
    #[test] fn reported_zone_and_empty_classifier_are_denied() {
        let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.destination.zone.as_mut().unwrap().stamp.authority = Authority::UntrustedReport; denied(r, DenialReason::UntrustedEvidence, CheckScope::Destination);
        r.destination.zone.as_mut().unwrap().stamp = lease(); r.destination.zone.as_mut().unwrap().classifier_revision = ""; denied(r, DenialReason::InvalidEvidence, CheckScope::Destination);
    }
    #[test] fn identity_and_lease_shape_are_validated() {
        let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.origin.identity.tenant_id = ""; denied(r, DenialReason::InvalidIdentity, CheckScope::Origin);
        r = request(Zone::Mainland, node(B, Zone::Mainland)); r.origin.role.stamp.valid_until = r.origin.role.stamp.issued_at; denied(r, DenialReason::InvalidEvidence, CheckScope::Origin);
    }
    #[test] fn every_relay_hop_keeps_original_client_zone() {
        let hops = [node(B, Zone::NonMainland)]; let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.path.hops = &hops;
        denied(r, DenialReason::CrossRegion, CheckScope::Hop(0));
    }
    #[test] fn same_zone_hops_are_allowed() { let hops = [node(B, Zone::Mainland)]; let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.path.hops = &hops; assert_eq!(decide(r), Decision::AllowBusiness); }
    #[test] fn relay_cannot_replace_original_principal() { let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.path.origin = B; denied(r, DenialReason::SubjectMismatch, CheckScope::Path); }
    #[test] fn partial_or_overlong_path_is_not_accepted() {
        let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.path.completeness = PathCompleteness::Incomplete; denied(r, DenialReason::IncompletePath, CheckScope::Path);
        let hops = [node(B, Zone::Mainland); MAX_MANAGED_HOPS + 1]; r.path.completeness = PathCompleteness::Complete; r.path.hops = &hops; denied(r, DenialReason::TooManyHops, CheckScope::Path);
    }
    #[test] fn server_origin_interconnection_is_not_client_partitioned() { let mut r = request(Zone::Mainland, node(B, Zone::NonMainland)); r.origin.role.role = DeviceRole::Server; r.origin.zone = None; assert_eq!(decide(r), Decision::AllowBusiness); r.authorization.kind = AuthorizationKind::Denied; denied(r, DenialReason::AuthorizationDenied, CheckScope::Authorization); }
    #[test] fn acl_denied_or_unavailable_remains_denied() {
        let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.authorization.kind = AuthorizationKind::Denied; denied(r, DenialReason::AuthorizationDenied, CheckScope::Authorization);
        r.authorization.kind = AuthorizationKind::Unavailable; denied(r, DenialReason::AuthorizationUnavailable, CheckScope::Authorization);
    }
    #[test] fn authorization_is_bound_to_original_pair_and_current_generation() {
        let mut r = request(Zone::Mainland, node(B, Zone::Mainland)); r.authorization.origin = B; denied(r, DenialReason::SubjectMismatch, CheckScope::Authorization);
        r.authorization.origin = A; r.authorization.destination = Resource::Node(C); denied(r, DenialReason::SubjectMismatch, CheckScope::Authorization);
        r.authorization.destination = r.destination.resource; r.authorization.stamp.policy_generation = 8; denied(r, DenialReason::StaleGeneration, CheckScope::Authorization);
    }
    #[test] fn authorized_cross_tenant_share_still_works_only_same_zone() { let mut r = request(Zone::Mainland, node(C, Zone::Mainland)); r.authorization.kind = AuthorizationKind::ShareGrant; assert_eq!(decide(r), Decision::AllowBusiness); r.destination.zone.as_mut().unwrap().zone = Some(Zone::NonMainland); denied(r, DenialReason::CrossRegion, CheckScope::Destination); }
    #[test] fn approved_private_attachment_and_gateway_work() { let hops = [node(B, Zone::Mainland)]; let mut r = request(Zone::Mainland, attachment("site-cn", Zone::Mainland)); r.path.hops = &hops; assert_eq!(decide(r), Decision::AllowBusiness); }
    #[test] fn private_attachment_cannot_inherit_gateway_zone() { let hops = [node(B, Zone::Mainland)]; let mut r = request(Zone::Mainland, attachment("site-other", Zone::NonMainland)); r.path.hops = &hops; denied(r, DenialReason::CrossRegion, CheckScope::Destination); }
    #[test] fn repeated_private_prefix_is_scoped_by_site() { let hops = [node(B, Zone::Mainland)]; let mut r = request(Zone::Mainland, attachment("site-cn", Zone::Mainland)); r.path.hops = &hops; r.destination.zone = attachment("site-other", Zone::Mainland).zone; denied(r, DenialReason::SubjectMismatch, CheckScope::Destination); }
    #[test] fn wrong_prefix_or_missing_gateway_is_denied() { let mut r = request(Zone::Mainland, attachment("site-cn", Zone::Mainland)); denied(r, DenialReason::MissingGateway, CheckScope::Path); r.destination.dialed_address = Some(ip("10.2.0.1")); denied(r, DenialReason::PrefixMismatch, CheckScope::Destination); }
    #[test] fn unbound_private_target_is_not_an_enrolled_node() { let d = Endpoint { resource: Resource::UnboundAddress(ip("10.1.2.3")), dialed_address: Some(ip("10.1.2.3")), zone: Some(evidence(Resource::UnboundAddress(ip("10.1.2.3")), Zone::Mainland)), node_address_binding: None, public_address_zone: None }; denied(request(Zone::Mainland, d), DenialReason::UnboundDestination, CheckScope::Destination); }
    #[test] fn ipv6_private_attachment_and_prefix_membership_work() { let resource = Resource::NetworkAttachment { tenant_id: "tenant-a", site_id: "site-v6", attachment_id: "ula", gateway: B, prefix: IpPrefix::new(ip("fd12:3456::"), 48).unwrap() }; let d = Endpoint { resource, dialed_address: Some(ip("fd12:3456::123")), zone: Some(evidence(resource, Zone::Mainland)), node_address_binding: None, public_address_zone: None }; let hops = [node(B, Zone::Mainland)]; let mut r = request(Zone::Mainland, d); r.path.hops = &hops; assert_eq!(decide(r), Decision::AllowBusiness); }
    #[test] fn prefix_constructor_rejects_default_routes_host_bits_and_mapped_prefixes() { assert!(IpPrefix::new(ip("0.0.0.0"), 0).is_none()); assert!(IpPrefix::new(ip("10.1.2.3"), 16).is_none()); assert!(IpPrefix::new(ip("::ffff:10.1.0.0"), 112).is_none()); assert!(IpPrefix::new(ip("fd12::"), 129).is_none()); }
    #[test] fn public_destination_uses_actual_dialed_ip() { let resource = Resource::PublicAddress(ip("8.8.8.8")); let mut d = Endpoint { resource, dialed_address: Some(ip("8.8.8.8")), zone: Some(evidence(resource, Zone::NonMainland)), node_address_binding: None, public_address_zone: None }; assert_eq!(decide(request(Zone::NonMainland, d)), Decision::AllowBusiness); d.dialed_address = Some(ip("1.1.1.1")); denied(request(Zone::NonMainland, d), DenialReason::AddressMismatch, CheckScope::Destination); }
    #[test] fn mapped_ipv6_cannot_escape_ipv4_classification() { let resource = Resource::PublicAddress(ip("8.8.8.8")); let d = Endpoint { resource, dialed_address: Some(ip("::ffff:8.8.8.8")), zone: Some(evidence(resource, Zone::NonMainland)), node_address_binding: None, public_address_zone: None }; denied(request(Zone::Mainland, d), DenialReason::CrossRegion, CheckScope::Destination); let bad = Resource::PublicAddress(ip("::ffff:10.1.2.3")); let d = Endpoint { resource: bad, dialed_address: Some(ip("::ffff:10.1.2.3")), zone: Some(evidence(bad, Zone::Mainland)), node_address_binding: None, public_address_zone: None }; denied(request(Zone::Mainland, d), DenialReason::UnboundDestination, CheckScope::Destination); }
    #[test] fn public_ipv6_and_dualstack_evidence_are_not_interchangeable() { let resource = Resource::PublicAddress(ip("2606:4700:4700::1111")); let mut d = Endpoint { resource, dialed_address: Some(ip("2606:4700:4700::1111")), zone: Some(evidence(resource, Zone::NonMainland)), node_address_binding: None, public_address_zone: None }; assert_eq!(decide(request(Zone::NonMainland, d)), Decision::AllowBusiness); d.zone = Some(evidence(Resource::PublicAddress(ip("1.1.1.1")), Zone::NonMainland)); denied(request(Zone::NonMainland, d), DenialReason::SubjectMismatch, CheckScope::Destination); }
    #[test] fn management_does_not_require_business_role_or_zone() { assert_eq!(management_decision(control()), Decision::AllowManagement); let mut c = control(); c.target.scheme = "wss"; c.route.operation = ManagementOperation::Heartbeat; assert_eq!(management_decision(c), Decision::AllowManagement); }
    #[test] fn management_operations_use_registered_routes_not_invented_paths() { for operation in [ManagementOperation::Bootstrap, ManagementOperation::Registration, ManagementOperation::Login, ManagementOperation::Configuration, ManagementOperation::Policy, ManagementOperation::Heartbeat, ManagementOperation::Health, ManagementOperation::ForwardControl] { let mut c = control(); c.route.operation = operation; assert_eq!(management_decision(c), Decision::AllowManagement); } }
    #[test] fn management_rejects_alternate_suffix_ip_and_trailing_dot_hosts() { for host in ["itachi.fans", "www.itachi.fans.evil.invalid", "evil-www.itachi.fans", "www.itachi.fans.", "1.1.1.1", "*.itachi.fans", "www.itachi.fans@evil.invalid"] { let mut c = control(); c.target.host = host; management_denied(c, DenialReason::InvalidManagementTarget); } }
    #[test] fn management_requires_tls_exact_port_and_no_userinfo_or_fragment() { for scheme in ["http", "ws", "httpsx"] { let mut c = control(); c.target.scheme = scheme; management_denied(c, DenialReason::InvalidManagementTarget); } let mut c = control(); c.target.effective_port = 8443; management_denied(c, DenialReason::InvalidManagementTarget); c = control(); c.target.userinfo_present = true; management_denied(c, DenialReason::InvalidManagementTarget); c = control(); c.target.fragment_present = true; management_denied(c, DenialReason::InvalidManagementTarget); }
    #[test] fn management_rejects_unverified_or_wrong_tls_peer() { let mut c = control(); c.tls_peer = TlsPeer::Unverified; management_denied(c, DenialReason::UnverifiedTls); c.tls_peer = TlsPeer::VerifiedHostname("other.itachi.fans"); management_denied(c, DenialReason::UnverifiedTls); }
    #[test] fn management_rejects_unregistered_claim_and_empty_route() { let mut c = control(); c.route.authority = RouteAuthority::UntrustedClaim; management_denied(c, DenialReason::UnregisteredControlRoute); c = control(); c.route.route_key = ""; management_denied(c, DenialReason::UnregisteredControlRoute); }
    #[test] fn business_frames_on_allowed_control_connection_are_not_exempt() { let mut c = control(); c.message_class = MessageClass::Business; management_denied(c, DenialReason::BusinessMessage); }
    #[test] fn management_never_bypasses_application_auth_or_cross_origin_redirect() { let mut c = control(); c.application_gate = ApplicationGate::Denied; management_denied(c, DenialReason::ApplicationDenied); c.application_gate = ApplicationGate::Unavailable; management_denied(c, DenialReason::ApplicationDenied); c = control(); c.redirect = RedirectEvidence::UnverifiedOrCrossOrigin; management_denied(c, DenialReason::UnsafeRedirect); c.redirect = RedirectEvidence::VerifiedSameOrigin; assert_eq!(management_decision(c), Decision::AllowManagement); }
    #[test] fn normalized_hostname_case_uses_verified_actual_origin() { let mut c = control(); c.target.host = "WWW.ITACHI.FANS"; c.tls_peer = TlsPeer::VerifiedHostname("WWW.ITACHI.FANS"); assert_eq!(management_decision(c), Decision::AllowManagement); c.target.host = " www.itachi.fans"; management_denied(c, DenialReason::InvalidManagementTarget); }
}

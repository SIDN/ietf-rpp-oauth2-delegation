%%%
title = "Secure Delegation Management for RESTful Provisioning Protocol (RPP)"
abbrev = "Secure Delegation Management for RPP"
area = "Internet"
workgroup = "Network Working Group"
submissiontype = "IETF"
keyword = [""]
TocDepth = 4
date = 2026-04-30

[seriesInfo]
name = "Internet-Draft"
value = "draft-wullink-rpp-oauth2-delegation-00"
stream = "IETF"
status = "standard"

[[author]]
initials="M."
surname="Wullink"
fullname="Maarten Wullink"
abbrev = ""
organization = "SIDN Labs"
  [author.address]
  email = "maarten.wullink@sidn.nl"
  uri = "https://sidn.nl/"

[[author]]
initials="P."
surname="Kowalik"
fullname="Pawel Kowalik"
abbrev = ""
organization = "DENIC"
  [author.address]
  email = "pawel.kowalik@denic.de"
  uri = "https://denic.de/"

%%%

.# Abstract

This document describes how OAuth 2.0 [@!RFC6749] can be used to allow a third party, such as a DNS Operator, to manage delegation (name server) details for a domain in the registry database on behalf of the registrant. It extends the RPP OAuth 2.0 authorization model defined in [@!I-D.wullink-rpp-oauth2] with mechanisms specific to third-party delegation management via the RESTful Provisioning Protocol (RPP) [@!I-D.wullink-rpp-core].

{mainmatter}

# Introduction

**NOTE:** This is a very early draft of how third-party delegation management could work in RPP. It is added here to provide a picture of the delegation flow and to facilitate discussion of the details and the security mechanisms that can be used to secure it. This document is expected to be significantly revised and updated as the delegation management flow and the security mechanisms are further developed and refined.

In the domain name system, delegation refers to the assignment of name servers responsible for a DNS zone. The registry holds authoritative delegation data — the name server (NS) records and associated glue records — for each domain in its database. Ordinarily only the sponsoring registrar, acting on behalf of the registrant, may update this data via the RPP API.

An increasingly common operational pattern is for a registrant to host their DNS with a dedicated DNS Operator that is not the sponsoring registrar. When the registrant wants the DNS Operator to manage their delegation settings — for example, to update name servers automatically — it is inconvenient and error-prone to require the registrant to relay every change through their registrar. Instead, the registrant should be able to grant the DNS Operator limited, revocable authority to update delegation data directly at the registry.

This document defines a mechanism based on OAuth 2.0 federation that enables this pattern securely and without any bilateral arrangement between the DNS Operator and the registrar. The registrant authenticates at the registrar's Authorization Server (AS) and grants explicit, domain-scoped consent for the DNS Operator to manage delegation data. The registrar's AS issues a signed JWT that the DNS Operator presents to the registry when submitting delegation update requests. The registry validates the token locally using the registrar's AS public key, which was registered during registrar accreditation, and authorises the update if the token is valid.

# Terminology

In this document the following terminology is used.

REST - Representational State Transfer ([@!REST]). An architectural style.

RESTful - A RESTful web service is a web service or API implemented using HTTP and the principles of [@!REST].

RESTful Provisioning Protocol or RPP - The protocol described in this document.

URL - A Uniform Resource Locator as defined in [@!RFC3986].

Resource - An object having a type, data, and possible relationship to other resources, identified by a URL.

RPP client - An HTTP user agent performing an RPP request.

RPP server - An HTTP server responsible for processing requests and returning results in any supported media type.

JWT - JSON Web Token as defined in [@!RFC7519].

Registrant - The holder of a registered domain name, who has an account at the sponsoring registrar.

Registrar - The accredited sponsoring registrar for a domain. The registrar operates an Authorization Server and maintains registrant accounts.

Registry - The authoritative operator of the top-level domain, operating the RPP server. The registry stores delegation data and validates access tokens.

DNS Operator - A third party (not the registrar) that manages DNS zones on behalf of registrants. The registrant has an account at the DNS Operator. The DNS Operator uses the RPP API to update delegation data at the registry.

Authorization Server (AS) - An OAuth 2.0 authorization server, operated by the registrar, that authenticates registrants and issues access tokens authorizing third parties to act on their behalf.

# Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT","SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [@!RFC2119].

In examples, indentation and white space in examples are provided only to illustrate element relationships and are not REQUIRED features of the protocol.

All example requests assume an RPP server using HTTP version 2 is listening on the standard HTTPS port on host rpp.example. An authorization token has been provided by an out of band process and MUST be used by the client to authenticate each request.

# Use Case

A registrant (`alice@example.com`) has registered `foo.example` through Registrar A. She has also signed up with DNS Operator B to host her DNS zones. She wants DNS Operator B to be able to update the name servers for `foo.example` in the registry database without having to route every change through Registrar A.

The desired outcome is:

1. DNS Operator B can update delegation data (name servers and glue records) for `foo.example` at the registry directly.
2. The authority is scoped to delegation management only — DNS Operator B cannot modify registrant contact data, initiate transfers, or perform any other operation.
3. The authority is granted explicitly by the registrant via an interactive OAuth 2.0 flow at Registrar A's AS.
4. The registry can verify the authority independently, without contacting Registrar A at request time.
5. The authority can be revoked by the registrant at any time, at which point the registry will no longer accept tokens issued for DNS Operator B.

# Authorization Request Details

OAuth 2.0 Rich Authorization Requests (RAR) [@!RFC9396] extends the standard OAuth 2.0 authorization request with an `authorization_details` parameter that carries a structured JSON object describing precisely what the client is requesting authorization for. Unlike scopes, which are coarse-grained string tokens, `authorization_details` allows the request to include typed, fine-grained authorization data, such as the specific domain name whose delegation data is to be managed. The AS can present this information to the registrant in a meaningful consent screen.

For the delegation management flow, the DNS Operator includes an `authorization_details` object of type `rpp_delegation` in the authorization request to the registrar's AS. The registrant sees exactly which domain they are consenting to allow the DNS Operator to manage. The AS MUST echo the `authorization_details` object back as a claim in the issued JWT, giving the registry verifiable, tamper-proof evidence of what was authorized and for which domain.

The `type` field MUST be set to `rpp_delegation`. Table (#tbl-rar) lists the RAR fields defined for RPP delegation management.

| Field | Type | Requirement | Description |
| ----- | ---- | ----------- | ----------- |
| `type` | String | REQUIRED | MUST be `rpp_delegation`. |
| `object_type` | String | REQUIRED | The RPP object type whose delegation data is to be managed. MUST be `domain`. |
| `object_identifier` | String | REQUIRED | The fully qualified domain name whose delegation data is to be managed (e.g., `foo.example`). |
| `actions` | Array of Strings | REQUIRED | The set of permitted delegation management actions. MUST contain one or more of: `read`, `update`. |
Table: RPP Delegation Authorization, RAR `authorization_details` object ([@!RFC9396])
{#tbl-rar}

Example RAR `authorization_details` value for managing delegation of `foo.example`:

```json
[{
  "type": "rpp_delegation",
  "object_type": "domain",
  "object_identifier": "foo.example",
  "actions": ["read", "update"]
}]
```

The registrar's AS MUST echo the `authorization_details` back as a claim in the issued JWT. The registry MUST validate the `authorization_details` claim in the token and MUST verify that `object_type` and `object_identifier` match the domain whose delegation data is being updated.

# Scopes

RPP OAuth 2.0 scopes are defined in [@!I-D.wullink-rpp-oauth2]. Delegation management uses the `domain:delegation:write` scope. This scope grants the bearer the right to update delegation data (name servers and glue records) for a specific domain, as further constrained by the `authorization_details` claim.

# Claims

RPP access tokens MUST conform to the JWT Profile for OAuth 2.0 Access Tokens defined in [@!RFC9068]. This profile establishes a standardized set of claims that RPP uses to make authorization decisions consistently across implementations and identity providers.

## RPP-Specific Claims

In addition to the standard [@!RFC9068] claims, table (#tbl-rpp-claims) lists the RPP-specific claims relevant to delegation management. Required claims MUST be present in every RPP delegation access token. Optional claims SHOULD be included when applicable.

| Claim | Requirement | Type | Description |
| ----- | ----------- | ---- | ----------- |
| `rpp_object_id` | OPTIONAL | String | The domain name whose delegation data may be managed. MUST be present when the `authorization_details` claim is not present. The value MUST be the fully qualified domain name (e.g., `foo.example`). The RPP server MUST validate that this value matches the domain in the update request. This claim MUST NOT be present when `authorization_details` is present. |
| `authorization_details` | REQUIRED | Array of Objects | Rich authorization details as defined by [@!RFC9396]. MUST be present in access tokens for the delegation management flow when RAR is used. Each object in the array MUST have a `type` field set to `rpp_delegation` and MUST include `object_type`, `object_identifier`, and `actions` fields (see (#tbl-rar)). The RPP server MUST validate that `object_type` and `object_identifier` match the domain in the update request, and that `actions` contains `update`. |
Table: RPP Delegation Access Token Claims
{#tbl-rpp-claims}

# Trust Model

The delegation management mechanism uses the registry as the central trust anchor, operating as a hub-and-spoke topology. Registrars establish a trust relationship with the registry during accreditation. DNS Operators MUST also be pre-registered with the registry in order to obtain access to the RPP API. This pre-registration is necessary to look up the sponsoring registrar's AS URI for a domain and to submit delegation update requests. No bilateral arrangement between the DNS Operator and the registrar is required; all delegation authority flows through the registrant's explicit consent at the registrar's AS.

**Registry as trust anchor.** As part of registrar onboarding, each registrar that operates its own AS (i.e., maintains registrant accounts) MUST register its AS metadata with the registry. This includes at minimum:

- The AS's authorization endpoint URI, used by the DNS Operator to construct the consent redirect.
- The AS's JWKS endpoint URI or the public key material itself, used by the registry to validate tokens issued by that AS.

The registry stores this metadata as part of the registrar's profile and makes it available via the discovery mechanism.

**Token validation without bilateral trust.** When the registry receives a delegation update request carrying a JWT issued by the registrar's AS, it validates the token locally using the registrar's AS public key that was registered at onboarding. No runtime call to the registrar or its AS is required. The registry already trusts that public key because it was registered through the accreditation process.

**DNS Operator.** The DNS Operator MUST be pre-registered with the registry to gain access to the RPP API. This pre-registration grants the DNS Operator the credentials necessary to query the registry's discovery endpoint (to look up the sponsoring registrar's AS URI for a given domain) and to submit delegation update requests on behalf of a registrant. The DNS Operator does not require any pre-existing relationship with the registrar; the only registrar-side requirement is that the registrar's AS accepts the DNS Operator's `redirect_uri` as a valid OAuth 2.0 client redirect URI.

**Security properties.** This model provides the following guarantees:

- A rogue DNS Operator cannot forge a delegation token that the registry will accept, because only the legitimate registrar's AS public key (registered at onboarding) can produce a valid signature.
- The DNS Operator cannot forge registrant consent, because the token is issued by the registrar's AS after the registrant has authenticated and approved the scope.
- The registry controls the set of trusted ASs by controlling which registrar AS metadata it accepts at onboarding.
- DNS Operators need no knowledge of registrar internals beyond what the registry exposes via the discovery endpoint. DNS Operators do require pre-registration with the registry to access the RPP API, but require no bilateral arrangement with any individual registrar.
- Tokens are scoped to a single domain and a specific set of actions, limiting the blast radius of a compromised token.

The following diagram shows how AS URIs and public keys flow through the registry and how the DNS Operator uses them to redirect the registrant's browser:

```ascii
  DNS Operator         Registry           Registrar
                     (Trust Anchor)
     |                    |                    |
     : --- Onboarding --------------------------:
     |                    |                    |
     |                    | Register AS        |
     |                    | URI + JWKS pubkey  |
     |                    |<-------------------|
     |                    |                    |
     : --- Delegation management time --------- :
     |                    |                    |
     | Discover Registrar |                    |
     | AS URI for domain  |                    |
     +------------------->|                    |
     |                    |                    |
     | AS URI returned    |                    |
     |<-------------------|                    |
     |                    |                    |
     | Redirect registrant's browser           |
     | to Registrar AS                         |
     +---------------------------------------->|
     |                    |                    |
     | Auth code returned via browser redirect |
     |<----------------------------------------|
     |                    |                    |
     | Exchange auth code |                    |
     | for access token   |                    |
     | (back-channel)     |                    |
     +---------------------------------------->|
     |                    |                    |
     | JWT (signed by     |                    |
     | Registrar AS)      |                    |
     |<----------------------------------------|
     |                    |                    |
     | Delegation update  |                    |
     | request + Bearer   |                    |
     | JWT                |                    |
     +------------------->|                    |
     |                    |                    |
     |                    | Validate JWT using |
     |                    | cached Registrar   |
     |                    | JWKS pubkey        |
     |                    | (no runtime call)  |
     |                    |                    |
     | Update result      |                    |
     |<-------------------|                    |
     |                    |                    |
```
Figure: RPP Delegation Trust Model — Onboarding, Discovery, and Token Flow

# Delegation Management Flow

The delegation management flow uses the OAuth 2.0 Authorization Code grant [@!RFC6749, Section 4.1] to obtain explicit, domain-scoped registrant consent directly from the registrar's AS. The primary method for conveying the authorization scope is Rich Authorization Requests (RAR) [@!RFC9396].

Before redirecting the registrant, the DNS Operator MUST first query the registry's discovery endpoint to resolve the sponsoring registrar's AS authorization URI for the domain. The sponsoring registrar is identified from the domain's current registrar data in the registry.

The authorization request MUST convey the specific domain and the set of requested actions so that the registrar's AS can present the registrant with an accurate consent screen.

The following diagram illustrates the complete delegation management flow:

```ascii
  Client          DNS             Registry        Registrar
(Registrant)    Operator                             AS
     |               |               |               |
     | 1. Request    |               |               |
     |  delegation   |               |               |
     |  mgmt for     |               |               |
     |  foo.example  |               |               |
     +-------------->|               |               |
     |               |               |               |
     |               | 2. Discover   |               |
     |               |  registrar    |               |
     |               |  AS URI for   |               |
     |               |  foo.example  |               |
     |               +-------------->|               |
     |               |               |               |
     |               | 3. Return     |               |
     |               |  registrar    |               |
     |               |  AS URI       |               |
     |               |<--------------|               |
     |               |               |               |
     | 4. Redirect   |               |               |
     |  to Registrar |               |               |
     |  AS (RAR:     |               |               |
     |  type=rpp_    |               |               |
     |  delegation,  |               |               |
     |  domain=      |               |               |
     |  foo.example, |               |               |
     |  actions=     |               |               |
     |  [update])    |               |               |
     |<--------------|               |               |
     |               |               |               |
     | 5. Auth &     |               |               |
     |  approve      |               |               |
     |  delegation   |               |               |
     |  scope at     |               |               |
     |  Registrar AS |               |               |
     +---------------------------------------------->|
     |               |               |               |
     | 6. Auth code  |               |               |
     |  + redirect   |               |               |
     |  to DNS Op    |               |               |
     |  callback URI |               |               |
     |<----------------------------------------------|
     |               |               |               |
     | 7. Follow     |               |               |
     |  redirect     |               |               |
     |  (auth code   |               |               |
     |  delivered)   |               |               |
     +-------------->|               |               |
     |               |               |               |
     |               | 8. Exchange   |               |
     |               |  auth code    |               |
     |               |  for access   |               |
     |               |  token        |               |
     |               |  (back-       |               |
     |               |  channel)     |               |
     |               +------------------------------>|
     |               |               |               |
     |               | 9. JWT        |               |
     |               |  (authz_      |               |
     |               |  details=     |               |
     |               |  {type:rpp_   |               |
     |               |  delegation,  |               |
     |               |  domain=      |               |
     |               |  foo.example, |               |
     |               |  actions=     |               |
     |               |  [update]})   |               |
     |               |<------------------------------|
     |               |               |               |
     |               | 10. Delegation|               |
     |               |  update       |               |
     |               |  request +    |               |
     |               |  Bearer JWT   |               |
     |               +-------------->|               |
     |               |               |               |
     |               |               | 11. Validate  |
     |               |               |  JWT (Reg.    |
     |               |               |  AS pubkey,   |
     |               |               |  verify type, |
     |               |               |  domain,      |
     |               |               |  actions)     |
     |               |               |               |
     |               |               | 12. Update    |
     |               |               |  delegation   |
     |               |               |  data for     |
     |               |               |  foo.example  |
     |               |               |               |
     |               | 13. Update    |               |
     |               |  successful   |               |
     |               |<--------------|               |
     |               |               |               |
     | 14. Delegation|               |               |
     |  update       |               |               |
     |  confirmed    |               |               |
     |<--------------|               |               |
     |               |               |               |
```
Figure: OAuth 2.0 Federated Delegation Management Flow

The steps in the diagram are as follows:

1. The registrant asks the DNS Operator to manage delegation data for `foo.example`.
2. The DNS Operator queries the registry's discovery endpoint to look up the sponsoring registrar's AS authorization URI. The registrar is identified from the current sponsoring registrar data for the domain in the registry.
3. The registry returns the sponsoring registrar's AS authorization URI. If no AS URI is registered for the sponsoring registrar, the DNS Operator cannot proceed with the OAuth 2.0 delegation flow and MUST inform the registrant that the registrar does not support this mechanism.
4. The DNS Operator redirects the registrant's browser to the registrar's AS. The authorization request MUST include an `authorization_details` parameter of type `rpp_delegation` with `object_type: "domain"`, `object_identifier: "foo.example"`, and `actions: ["read", "update"]` (RAR, [@!RFC9396]). The DNS Operator's callback URI MUST be included as the OAuth 2.0 `redirect_uri`.
5. The registrant authenticates at the registrar's AS and explicitly approves the delegation scope, providing verifiable consent for the DNS Operator to manage delegation data for the specified domain.
6. The registrar's AS issues an authorization code and redirects the registrant's browser back to the DNS Operator's registered callback URI.
7. The registrant's browser follows the redirect, delivering the authorization code to the DNS Operator's callback endpoint.
8. The DNS Operator exchanges the authorization code for an access token at the registrar's AS token endpoint (back-channel, Authorization Code grant [@!RFC6749, Section 4.1]).
9. The registrar's AS validates the code and issues a signed JWT access token ([@!RFC9068]). The token MUST contain an `authorization_details` claim echoing the `rpp_delegation` object, including `object_type`, `object_identifier`, and `actions`.
10. The DNS Operator submits the delegation update request to the registry RPP API, including the JWT as a Bearer token in the `Authorization` header. The request targets the delegation sub-resource of the domain (e.g., `PATCH /domains/foo.example/delegation`).
11. The registry validates the JWT locally using the sponsoring registrar's AS public key (obtained via OAuth 2.0 Authorization Server Metadata [@!RFC8414]). No live call to the registrar is required. The registry MUST verify that the `authorization_details` claim contains an `rpp_delegation` object whose `object_identifier` matches the domain in the request URL and whose `actions` contains `update`.
12. The registry updates the delegation data (name servers and any associated glue records) for `foo.example`.
13. The registry returns a successful update response to the DNS Operator.
14. The DNS Operator confirms the completed delegation update to the registrant.

# Data Objects

The RPP Data Object Catalog is extended to include each registrar's AS metadata.

- Auth Server Metadata Object: This object describes the `authorization_server` for each registrar that operates its own AS. It contains the metadata necessary for a DNS Operator to interact with the registrar's AS, including the authorization endpoint URI and JWKS URI or public key material.

TODO

# Endpoints

The Secure Delegation Management mechanism relies on the following RPP endpoints:

- Domain discovery endpoint: returns the sponsoring registrar's AS authorization URI for a given domain name. Used by the DNS Operator to determine where to redirect the registrant.
- Delegation sub-resource endpoint (e.g., `PATCH /domains/{domainId}/delegation`): accepts delegation update requests from DNS Operators bearing a valid `rpp_delegation` JWT.

TODO

# IANA Considerations

TODO

# Internationalization Considerations

TODO

# Security Considerations

**Token scope.** Tokens issued in this flow are scoped to a single domain name and to the specific set of actions granted by the registrant. The registry MUST reject tokens that do not contain an `rpp_delegation` `authorization_details` object whose `object_identifier` exactly matches the domain in the request URL.

**Token lifetime.** Access tokens for delegation management MAY have a longer lifetime than tokens used for single-use operations such as object transfers, since they may be used for repeated updates. However, token lifetime MUST be bounded. Registrar ASs SHOULD issue tokens with a lifetime appropriate for the expected operational pattern, and MUST support token revocation.

**Revocation.** Registrars MUST support token revocation ([@!RFC7009]) so that registrants can revoke a DNS Operator's access at any time. The registry MUST check token revocation status before processing delegation update requests if the registrar's AS publishes a revocation endpoint.

**Consent granularity.** The RAR `authorization_details` object allows the registrant to see exactly which domain and which actions they are consenting to. Registrar ASs MUST surface this information clearly on the consent screen.

**DNS Operator authentication.** The registrar's AS MUST authenticate the DNS Operator as an OAuth 2.0 client before issuing tokens. At minimum, the DNS Operator MUST be registered as a confidential OAuth 2.0 client at the registrar's AS or use a publicly verifiable client authentication method.

# Change History

## Version 00

- Created initial draft with core concepts and delegation management flow.

{backmatter}

{numbered="false"}
# Acknowledgements

TODO

<reference anchor="REST" target="http://www.ics.uci.edu/~fielding/pubs/dissertation/rest_arch_style.htm">
  <front>
    <title>Architectural Styles and the Design of Network-based Software Architectures</title>
    <author initials="R." surname="Fielding" fullname="Roy Fielding">
      <organization/>
    </author>
    <date year="2000"/>
  </front>
</reference>

<reference anchor="I-D.wullink-rpp-oauth2" target="https://sidn.github.io/ietf-rpp-oauth2/draft-wullink-rpp-oauth2.html">
  <front>
    <title>RESTful Provisioning Protocol (RPP) - OAuth 2.0</title>
    <author initials="M." surname="Wullink" fullname="Maarten Wullink">
      <organization>SIDN Labs</organization>
    </author>
    <author initials="P." surname="Kowalik" fullname="Pawel Kowalik">
      <organization>DENIC</organization>
    </author>
    <date year="2026"/>
  </front>
  <seriesInfo name="Internet-Draft" value="draft-wullink-rpp-oauth2-00"/>
</reference>

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

This document describes how OAuth 2.0 [@!RFC6749] enables a third party, such as a DNS Operator, to manage delegation (name server) details for a domain on behalf of the registrant using the RESTful Provisioning Protocol (RPP). It extends the RPP OAuth 2.0 authorization model defined in [@!I-D.wullink-rpp-oauth2] with mechanisms specific to third-party delegation management via the RESTful Provisioning Protocol (RPP) [@!I-D.wullink-rpp-core].

{mainmatter}

# Introduction

**NOTE:** This is a very early draft of how third-party delegation management could work in RPP. It is added here to provide an idea of the possible delegation flow and to facilitate discussion. This document is expected to be significantly revised and updated as the delegation management flow and the security mechanisms are further developed and refined.

In the domain name system, delegation refers to the assignment of name servers responsible for a DNS zone. The registry holds authoritative delegation data. The name server (NS) records and associated glue records for each domain in its database. Ordinarily only the sponsoring registrar, acting on behalf of the registrant, may update this data via the RPP API.

An increasingly common operational pattern is for a registrant to host their DNS with a dedicated DNS Operator that is not the sponsoring registrar. When the registrant wants the DNS Operator to manage their delegation settings it is inconvenient and error-prone to require the registrant to relay every change through their registrar or configure it manually using registrar provided tools. Instead, the registrant should be able to grant the DNS Operator limited, revocable authority to update delegation data directly at the registry using the RPP API.

This document defines a mechanism based on OAuth 2.0 federation that enables this pattern securely and without any bilateral arrangement between the DNS Operator and the registrar. The registrant authenticates at the registrar's Authorization Server (AS) and grants explicit, domain-scoped consent for the DNS Operator to manage delegation data. The registrar's AS issues a signed access token that the DNS Operator presents to the registry when submitting an RPP domain update requests. The registry validates the token locally using the registrar's AS public key and authorises the update if the token is valid.

# Terminology

In this document the following terminology is used.

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

A registrant has registered `foo.example` through Registrar A and has also signed up with DNS Operator B to host the DNS zones for `foo.example`. The registrant wants DNS Operator B to be able to update the name servers for `foo.example` in the registry database without having to route every change through Registrar A.

The desired outcome is:

1. DNS Operator B can update delegation data (name servers and glue records) for `foo.example` at the registry directly.
2. The authority is scoped to delegation management only, e.g. DNS Operator B cannot modify registrant contact data, initiate transfers, or perform any other operation.
3. The authority is granted explicitly by the registrant via an interactive OAuth 2.0 flow at Registrar A's AS.
4. The registry can verify the authority independently, without contacting Registrar A at request time.
5. The authority can be revoked by the registrant at any time, at which point the registry will no longer accept tokens issued for DNS Operator B.

# Authorization Request Details

OAuth 2.0 Rich Authorization Requests (RAR) [@!RFC9396] extends the standard OAuth 2.0 authorization request with an `authorization_details` parameter that carries a structured JSON object describing precisely what the client is requesting authorization for. Unlike scopes, which are coarse-grained string tokens, `authorization_details` allows the request to include typed, fine-grained authorization data, such as the specific domain name whose delegation data is to be managed. The AS can present this information to the registrant in a meaningful consent screen.

For the delegation management flow, the DNS Operator includes an `authorization_details` object of type `delegation` in the authorization request to the registrar's AS. The registrant sees exactly which domain they are consenting to allow the DNS Operator to manage. The AS MUST echo the `authorization_details` object back as a claim in the issued JWT, giving the registry verifiable, tamper-proof evidence of what was authorized and for which domain.

The `type` field MUST be set to `delegation`. Table (#tbl-rar) lists the RAR fields defined for RPP delegation management.

| Field | Type | Requirement | Description |
| ----- | ---- | ----------- | ----------- |
| `type` | String | REQUIRED | MUST be `delegation`. |
| `object_type` | String | REQUIRED | The RPP object type whose delegation data is to be managed. MUST be `domain`. |
| `object_identifier` | String | REQUIRED | The unique identifier of the specific domain whose delegation data is to be managed (e.g., `foo.example`). |
Table: RPP Delegation Authorization, RAR `authorization_details` object ([@!RFC9396])
{#tbl-rar}

Example RAR `authorization_details` value for managing delegation of `foo.example`:

```json
[{
  "type": "delegation",
  "object_type": "domain",
  "object_identifier": "foo.example"
}]
```

<!-- If we keep using RAR then the rar schema should be standardized in rpp-oauth2 doc and here only require the use of the specific type: delegation -->

The registrar's AS MUST echo the `authorization_details` back as a claim in the issued JWT. The registry MUST validate the `authorization_details` claim in the token and MUST verify that `object_type` and `object_identifier` match the domain whose delegation data is being updated.

When the registrar's AS does not support RAR ([@!RFC9396]), the specific object being managed MUST be conveyed via the `rpp_op_type`, `rpp_object_type` and `rpp_object_identifier` claims rather than encoded in the `authorization_details` claim. The `rpp_op_type` claim MUST be set to `delegation`. The `rpp_object_type` claim MUST be set to the RPP object type being managed, for delegation type this MUST be `domain`. The `rpp_object_identifier` claim MUST be set to the specific domain being managed (e.g., `foo.example`). The registry MUST validate that these claim values match the domain being managed.

# Scopes

RPP OAuth 2.0 scopes are defined in [@!I-D.wullink-rpp-oauth2]. Delegation management introduces new delegation specific scopes: `delegation:read`. This scope grants the bearer the right to update delegation data (name servers and glue records) for a specific domain, as further constrained by the `authorization_details` claim.

Table (#tbl-scopes) defines the the new OAuth 2.0 scopes for Delegation Management. Each scope grants a specific set of permissions on the RPP domain resource. The registry MUST enforce that the access token presented in a delegation update request contains the appropriate scope(s) for the requested operation.

| Scope | Data Object | Operations Granted |
| ----- | ----------- | ------------------ |
| `delegation:read` | Domain Name | Read delegation data |
| `delegation:update` | Domain Name | Update delegation data |
Table: RPP OAuth 2.0 Scopes for Delegation Management
{#tbl-scopes}

# Claims

The delegation management flow uses the same RPP-specific claims defined in [@!I-D.wullink-rpp-oauth2]. No new claims are introduced for delegation management.

# Trust Model

The delegation management mechanism uses the registry as the central trust anchor, operating as a hub-and-spoke topology. Registrars establish a trust relationship with the registry during accreditation. DNS Operators MUST also be pre-registered with the registry in order to obtain access to the RPP API. No bilateral arrangement between the DNS Operator and the registrar is required; all delegation authority flows through the registrant's explicit consent at the registrar's AS.

**Registry as trust anchor.** As part of registrar onboarding, each registrar that operates its own AS (i.e., maintains registrant accounts) MUST register its AS metadata with the registry. This includes at minimum:

- The AS's authorization endpoint URI, used by the DNS Operator to construct the consent redirect.
- The AS's JWKS endpoint URI or the public key material itself, used by the registry to validate tokens issued by that AS.
- TODO

The registry stores this metadata as part of the registrar's profile and makes it available to approved DNS operators as part of the delegation update flow.

**Token validation without bilateral trust.** When the registry receives a delegation update request carrying a JWT issued by the registrar's AS, it validates the token locally using the registrar's AS public key that was registered at onboarding. No runtime call to the registrar or its AS is required. The registry already trusts that public key because it was registered through the accreditation process.

**DNS Operator.** The DNS Operator MUST be pre-registered with the registry to gain access to the RPP API. This pre-registration grants the DNS Operator the credentials necessary to query the RPP registrar info endpoint (to look up the sponsoring registrar's AS URI for a given domain) and to submit delegation update requests on behalf of a registrant. The DNS Operator does not require any pre-existing relationship with the registrar; the only registrar-side requirement is that the registrar's AS accepts the DNS Operator's `redirect_uri` as a valid OAuth 2.0 client redirect URI.

**Security properties.** This model provides the following guarantees:

- A rogue DNS Operator cannot forge a delegation token that the registry will accept, because only the legitimate registrar's AS public key (registered at onboarding) can produce a valid signature.
- The DNS Operator cannot forge registrant consent, because the token is issued by the registrar's AS after the registrant has authenticated and approved the scope.
- The registry controls the set of trusted ASs by controlling which registrar AS metadata it accepts at onboarding.
- DNS Operators need no knowledge of registrar internals beyond what the registry exposes via the discovery endpoint. DNS Operators do require pre-registration with the registry to access the RPP API, but require no bilateral arrangement with any individual registrar.
- Tokens are scoped to a single domain and a specific set of actions, limiting the impact of a compromised token.

# Delegation Management Flow

The delegation management flow uses the OAuth 2.0 Authorization Code grant [@!RFC6749, Section 4.1] to obtain explicit, domain-scoped registrant consent directly from the registrar's AS. The primary method for conveying the authorization scope is Rich Authorization Requests (RAR) [@!RFC9396].

Before redirecting the registrant, the DNS Operator MUST first query the registry's discovery endpoint to resolve the sponsoring registrar's AS authorization URI for the domain. The sponsoring registrar is identified from the domain's current registrar data in the registry.

The authorization request MUST convey the specific domain and the set of requested actions so that the registrar's AS can present the registrant with an accurate consent screen.

The following diagram illustrates the complete delegation management flow:

```ascii
  Client        DNS Operator       Registry          Registrar
(Registrant)                     (Trust Anchor)         AS
     |               |                |                  |
     : --- Onboarding ---------------------------------- :
     |               |                |                  |
     |               | 1. Register    |                  |
     |               | DNS Operator   |                  |
     |               | account        |                  |
     |               +--------------->|                  |
     |               |                |                  |
     |               | 2. Account     |                  |
     |               | credentials    |                  |
     |               | returned       |                  |
     |               |<---------------|                  |
     |               |                |                  |
     |               |                | 3. Register AS   |
     |               |                | URI + JWKS pubkey|
     |               |                |<-----------------|
     |               |                |                  |
     : --- Delegation management time ------------------- :
     |               |                |                  |
     | 4. Request    |                |                  |
     | delegation    |                |                  |
     | mgmt for      |                |                  |
     | foo.example   |                |                  |
     +-------------->|                |                  |
     |               |                |                  |
     |               | 5. Discover    |                  |
     |               | Reg. AS URI    |                  |
     |               | for domain     |                  |
     |               +--------------->|                  |
     |               |                |                  |
     |               | 6. AS URI      |                  |
     |               | returned       |                  |
     |               |<---------------|                  |
     |               |                |                  |
     | 7. Redirect   |                |                  |
     | to Registrar  |                |                  |
     | AS            |                |                  |
     |<--------------|                |                  |
     |               |                |                  |
     | 8. Auth &     |                |                  |
     | approve       |                |                  |
     | delegation    |                |                  |
     | scope         |                |                  |
     +-------------------------------------------------->|
     |               |                |                  |
     | 9. Auth code  |                |                  |
     | + redirect to |                |                  |
     | DNS Op        |                |                  |
     | callback URI  |                |                  |
     |<--------------------------------------------------|
     |               |                |                  |
     | 10. Follow    |                |                  |
     | redirect      |                |                  |
     | (auth code    |                |                  |
     | delivered)    |                |                  |
     +-------------->|                |                  |
     |               |                |                  |
     |               | 11. Exchange   |                  |
     |               | auth code for  |                  |
     |               | access token   |                  |
     |               | (back-channel) |                  |
     |               +---------------------------------->|
     |               |                |                  |
     |               | 12. JWT signed |                  |
     |               | by Registrar AS|                  |
     |               |<----------------------------------|
     |               |                |                  |
     |               | 13. Delegation |                  |
     |               | update request |                  |
     |               | + Bearer JWT   |                  |
     |               +--------------->|                  |
     |               |                |                  |
     |               |                | 14. Validate JWT |
     |               |                | using cached Reg.|
     |               |                | JWKS pubkey      |
     |               |                | (no runtime call)|
     |               |                |                  |
     |               |                | 15. Notify       | 
     |               | 16. Update.    |     Registrar    |
     |               | result         |----------------->|
     |               |<---------------|                  |
     |               |                |                  |
     | 17. Delegation|                |                  |
     | update        |                |                  |
     | confirmed     |                |                  |
     |<--------------|                |                  |
     |               |                |                  |
```
Figure: RPP Delegation Trust Model — Onboarding, Discovery, and Token Flow

The steps in the diagram are as follows:

1. During DNS Operator onboarding, the DNS Operator registers an account with the registry to obtain API credentials. The registry grants the DNS Operator access to the RPP API endpoints needed for delegation management, including the registrar discovery endpoint and the delegation update endpoint.
2. The registry returns the API credentials to the DNS Operator.
3. During registrar onboarding, the registrar registers its AS authorization endpoint URI and JWKS public key material with the registry. The registry stores this as part of the registrar's profile.
4. The registrant asks the DNS Operator to manage delegation data for `foo.example`.
5. The DNS Operator queries the registry's RPP registrar info endpoint, providing the domain name, to look up the sponsoring registrar's AS authorization URI.
6. The registry returns the sponsoring registrar's AS authorization URI. If no AS URI is registered for the sponsoring registrar, the delegation management flow cannot proceed and the DNS Operator MUST inform the registrant that the registrar does not support this mechanism.
7. The DNS Operator redirects the registrant's browser to the registrar's AS with an authorization request that includes an `authorization_details` parameter of type `delegation` with `object_type: "domain"`, `object_identifier: "foo.example"` (RAR, [@!RFC9396]). The DNS Operator's callback URI MUST be included as the OAuth 2.0 `redirect_uri`.
8. The registrant authenticates at the registrar's AS and approves the delegation scope.
9. The registrar's AS issues an authorization code and redirects the registrant's browser back to the DNS Operator's registered callback URI.
10. The registrant's browser follows the redirect, delivering the authorization code to the DNS Operator's callback endpoint.
11. The DNS Operator exchanges the authorization code for an access token at the registrar's AS token endpoint (back-channel, Authorization Code grant [@!RFC6749, Section 4.1]).
12. The registrar's AS validates the code and issues a signed JWT access token ([@!RFC9068]) containing an `authorization_details` claim that echoes the received `authorization_details` claim.
13. The DNS Operator submits the delegation update request to the registry RPP API, including the JWT as a Bearer token in the `Authorization` header. The request targets the delegation sub-resource of the domain (e.g., `PATCH /domains/foo.example/delegation`).
14. The registry validates the JWT locally using the sponsoring registrar's AS public key (obtained via OAuth 2.0 Authorization Server Metadata [@!RFC8414]). No live call to the registrar is required. The registry MUST verify that the `authorization_details` claim contains an `object_identifier` that matches the domain in the request.
15. Notify the registrar of the delegation update, so that the registrar can reflect the change in its own systems and provide accurate information to the registrant.
16. The registry updates the delegation data (name servers and any associated glue records) for `foo.example` and returns the result to the DNS Operator.
17. The DNS Operator confirms the completed delegation update to the registrant.

# Data Objects

The RPP Data Object Catalog is extended to include each registrar's AS metadata.

- Auth Server Metadata Object: This object describes the `authorization_server` for each registrar that operates its own AS. It contains the metadata necessary for a DNS Operator to interact with the registrar's AS, including the authorization endpoint URI and JWKS URI or public key material.
- 

**TODO** Add model of the actual data objects for delegation management, e.g. the delegation sub-resource of the domain object, and the expected request and response formats for delegation update requests.

TODO

# Endpoints

The Secure Delegation Management mechanism relies on the following RPP endpoints:

- Registrar info endpoint: returns the sponsoring registrar's AS authorization URI for a given domain name. Used by the DNS Operator to determine where to redirect the registrant.
- Delegation sub-resource endpoint (e.g., `PATCH /domains/{domainId}/delegation`).

TODO

# IANA Considerations

TODO

# Internationalization Considerations

TODO

# Security Considerations

**Token scope.** Tokens issued in this flow are scoped to a single domain name and to the specific set of actions granted by the registrant. The registry MUST reject tokens that do not contain an `authorization_details` object whose `object_identifier` exactly matches the domain in the request URL.

**Token lifetime.** Access tokens for delegation management MAY have a longer lifetime than tokens used for single-use operations such as object transfers, since they may be used for repeated updates. However, token lifetime MUST be bounded. Registrar ASs SHOULD issue tokens with a lifetime appropriate for the expected operational pattern, and MUST support token revocation.

**Revocation.** Registrars MUST support token revocation ([@!RFC7009]) so that registrants can revoke a DNS Operator's access at any time. The registry MUST check token revocation status before processing delegation update requests if the registrar's AS publishes a revocation endpoint.

**Consent granularity.** The RAR `authorization_details` object allows the registrant to see exactly which domain and which actions they are consenting to. Registrar ASs MUST surface this information clearly on the consent screen.

# Change History

## Version 00

- Created initial draft with core concepts and delegation management flow.

{backmatter}

{numbered="false"}
# Acknowledgements

TODO

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

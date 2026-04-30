# Secure Delegation Management for RESTful Provisioning Protocol (RPP)

This repository contains the IETF draft for enabling third-party delegation management in the RESTful Provisioning Protocol using OAuth 2.0. It defines a mechanism that allows a DNS Operator to manage delegation (name server) details for a domain in the registry database on behalf of the registrant, using an OAuth 2.0 federated authorization flow.

The [draft](https://github.com/SIDN/ietf-rpp-oauth2-delegation/blob/main/src/draft-wullink-rpp-oauth2-delegation.md) is authored using [mmark](https://mmark.miek.nl/) Markdown.

Contributions in the form of a Pull Request are welcome.

For generated output see:   
[Plaintext](https://sidn.github.io/ietf-rpp-oauth2-delegation/draft-wullink-rpp-oauth2-delegation.txt)  
[HTML](https://sidn.github.io/ietf-rpp-oauth2-delegation/draft-wullink-rpp-oauth2-delegation.html)  
[PDF](https://sidn.github.io/ietf-rpp-oauth2-delegation/draft-wullink-rpp-oauth2-delegation.pdf)  
[XML](https://sidn.github.io/ietf-rpp-oauth2-delegation/draft-wullink-rpp-oauth2-delegation.xml)  

## Contributing

See the
[guidelines for contributions](https://github.com/SIDN/ietf-rpp-oauth2-delegation/blob/main/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.

## Command Line Usage

Requirements:

- [mmark](https://mmark.miek.nl/)
- [xml2rfc](https://github.com/ietf-tools/xml2rfc#installation)

Formatted versions can be built using:

```sh
cd src
make all
```

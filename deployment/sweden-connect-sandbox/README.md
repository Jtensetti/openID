# Tjipp — Sweden Connect Sandbox

Status 2026-11-02: source-code preparation only. Not deployed, registered, externally tested, or Digg approved.

## Strict separation

This is a synthetic-only IdP. It must run in a separate process, OS account, key directory,
domain and TLS proxy from the real-pass phone pilot. It MUST NOT use the real identity
registry or any real person's passport. It MAY only assert the
urn:openid:lab:simulated context; LoA3 requests must be rejected. The synthetic
test credentials are reset each launch and expire after one hour.

The code provides:
- sandbox-init: generates disposable TLS/SAML keys, a distinct RSA-3072 federation signing
  key and exact pinned *public* Sweden Connect Sandbox SAML/OIDC trust anchors.
- sandbox-idp: exposes only the synthetic IdP on loopback 127.0.0.1:9443.
- Signed SAML SP metadata from the Sandbox federation (verified using Digg's
  metadata signing certificate) instead of locally fabricated SP metadata.
- OpenID Federation 1.0 Entity Configuration generation and signed federation
  statements through Sweden Connect Spring Authentication Server 1.0.3,
  with OP registration intermediate and trust-anchor-based RP resolution.

There is no LoA3 approval, federation Trust Mark or general-purpose external identity
issuance. Full OIDC Signature Extension and external profile conformance remain untested.

## Preconditions not handled by this code

1. Digg administrator access (requested via email to swedenconnect@digg.se).
2. Dedicated DNS idp-sandbox.tensetti.io pointing to a separate sandbox host.
   This hostname is a proposed name and has not been provisioned by this change.
3. Publicly trusted HTTPS/TLS certificate for that domain, correctly deployed.
4. A publicly reachable SVG logo at /logo.svg. The repo's existing
   prototype/src/main/resources/static/wallet/icon.svg can be a *temporary internal
   test placeholder*, but Digg may require an approved brand logotype.
5. A successful local CI build and a tested separate deployment. Never reload
   the existing private beta or expose its keys/services.

## Build and run — separate host, JDK 21, Linux

Run from repository root:

~~~sh
cd prototype
./mvnw -B -ntp clean verify
mkdir -p /srv/tjipp-sandbox
cp ../deployment/sweden-connect-sandbox/settings.example.json /srv/tjipp-sandbox/settings.json
java -jar target/isolated-eid-lab.jar sandbox-init /srv/tjipp-sandbox/keys
java -jar target/isolated-eid-lab.jar sandbox-idp /srv/tjipp-sandbox/keys /srv/tjipp-sandbox/settings.json
~~~

Sandbox initialization refuses an existing directory and creates test-only
certificates valid for 30 days. The disposable key stores use the lab-only
password and MUST NOT be used for QA, production or real identities.
Keep the generated directory outside GitHub with restricted filesystem rights
under a dedicated unprivileged service user.

Use the provided nginx.example.conf as an ingress *template* only. Correct
TLS paths for the host and copy an approved logo to
/var/www/tjipp-sandbox/logo.svg. It verifies the dedicated localhost
TLS certificate; preserve this verification. Never put HTTP Basic
authentication on public SSO, metadata, OIDC or token endpoints.

The published SAML entityID is:

    https://idp-sandbox.tensetti.io/idp

The OIDC Entity Identifier / issuer is:

    https://idp-sandbox.tensetti.io

## Before submitting to Digg

From another computer, confirm all three endpoints respond over trusted TLS:

~~~sh
curl -fsS https://idp-sandbox.tensetti.io/saml2/metadata -o tjipp-idp.xml
curl -fsS https://idp-sandbox.tensetti.io/.well-known/openid-federation -o tjipp-entity.jwt
curl -fsS https://idp-sandbox.tensetti.io/.well-known/openid-configuration -o tjipp-discovery.json
~~~

Inspect the SAML XML for one IDPSSODescriptor, correct entityID, signature
certificate, SSO endpoint and absence of unapproved LoA. Validate the XML
using https://validator.swedenconnect.se/. The OIDC endpoint should serve
a signed JWT with typ=entity-statement+jwt, iss=sub=our issuer, active
federation jwks, authority_hints including
https://fed.sandbox.swedenconnect.se/im-reg-sc-op, metadata.openid_provider
with the same issuer and valid logo and contact information.
Verify the JWT signature using a trusted JOSE library against the published
JWK; decoding the JWT is NOT signature verification.

A live well-known endpoint does not mean the federation has registered or
trusted the entity. Digg must publish a Subordinate Statement for the OP.

## SAML registration after Digg grants login

At https://md.sandbox.swedenconnect.se/mdreg/home :

1. Validate the *generated* tjipp-idp.xml via Metadata Validator.
2. Add a new metadata record.
3. Name = Tjipp Sandbox – synthetic Identity Provider
4. Metadata = complete, generated XML (not an edited demonstration).
5. Save; check publication in
   https://md.sandbox.swedenconnect.se/metadata/mdx/role/idp.xml

The published signed SP feed used by our IdP is
https://md.sandbox.swedenconnect.se/metadata/mdx/role/sp.xml .
The public signing certificate is pinned. Do not disable validation on error.

## OIDC registration after Digg grants administrator login

At https://portal.sandbox.swedenconnect.se/ :

1. Under the organization, register an OpenID Provider Entity.
2. Entity Identifier = https://idp-sandbox.tensetti.io
3. The portal reads the signed Entity Configuration at
   https://idp-sandbox.tensetti.io/.well-known/openid-federation
4. Confirm contacts, logo, signing key, organization and intermediate.
5. Do NOT assert a LoA Trust Mark. Record all portal profile-conformance
   errors without declaring the work completed.

The current simulated context may be rejected by Digg's OIDC profile
conformance check, and OIDC Signature Extension remains to be exercised.
That is an open integration gap, not a reason to fabricate LoA3.

## External test cases

At https://testclient.sandbox.swedenconnect.se/ :

1. Choose SAML Authentication, the test client's signed Service Provider,
   and the Tjipp Sandbox IdP.
2. Select HTTP-Redirect, a correctly signed request, ForceAuthn=true,
   IsPassive=false. Request no LoA3. Either omit RequestedAuthnContext
   or specify urn:openid:lab:simulated if free-form ACR is supported.
3. Submit; at the synthetic IdP, acknowledge simulated proofing
   and enter TEST-CREDENTIAL-alice. Never supply a real pass/personnummer.
4. Inspect Authentication Result: correct response signature, registered IdP
   signing key, InResponseTo, audience, recipient, timestamps, synthetic
   identity and simulated auth context.
5. Run negative tests: unsigned request, wrong signing key, wrong issuer/ACS,
   replay, expired request, IsPassive=true, and LoA3. These must fail
   or respond with appropriate SAML status, not authenticate.

Once the OP is registered, resolve an external RP via the Sandbox
Trust Anchor and exercise OIDC Authorization Code + PKCE. Check correct
iss, audience, nonce, auth_time and callback, signature, and negative
redirect/nonce/replay cases. SignRequest/Signature Extension is NOT
counted as tested until an external client verifies its behavior.

## Evidence for Digg and independent reviewers

Save (privately): Git commit SHA, CI run URL, generated metadata XML and
SHA-256, signed Entity Configuration and verified signature result,
external metadata validator result, signed external client results,
negative tests and timestamps, and a written disclosure that all
identities/keys are synthetic. Never put credential data, private keys,
sessions, real identity information or screenshots containing sensitive
payloads in a public GitHub issue or PR.

This proves *technical interoperability in Sandbox* if and when the
external cases pass. It does not prove Digg certification, official
assurance level 3, approved identity proofing, live eID issuance, or any
right to funding.

## Pinned trust material and rollover

As published by Sweden Connect for Sandbox on 2026-10-22:
- SAML signing certificate SHA-256:
  86b5306355636b184de4b0e29c7c417429ece79164fb4680acf0b5f28b1cc0ea
- OpenID Federation Sandbox Trust Anchor EC P-521 public JWK kid:
  x8vWKOCUciPdbte5wyXkY4404TSwi8cok3Zrfj-f7PQ

If Digg rotates keys, review the *official* source before committing updated
public anchors. The loader rejects substituted/mismatched keys. The
temporary test key expiry requires replacing and registering updated
metadata; it is NOT a full production key-rollover implementation.

Primary official references:
- https://sandbox.swedenconnect.se/home/register.html
- https://sandbox.swedenconnect.se/home/saml.html
- https://docs.swedenconnect.se/federation/oidf-structure.html
- https://docs.swedenconnect.se/federation/oidc-metadata-requirements.html
- https://github.com/swedenconnect/spring-authentication-server/blob/v1.0.3/docs/openid-provider.md#openid-federation

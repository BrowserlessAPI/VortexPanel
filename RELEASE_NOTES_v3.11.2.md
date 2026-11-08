# VortexPanel 3.11.2

## New: SSL certificate choices

The SSL tab of every website (nginx and Apache) now offers four kinds of certificate.

**Let's Encrypt (free).** Unchanged default. Issued with a file check on port 80
or a DNS record (needed for wildcards).

**ZeroSSL (free, 90 days).** Issued the same way as Let's Encrypt. Connect your
ZeroSSL account with its e-mail address or its EAB keys (ZeroSSL dashboard >
Developer). Renewals stay with the provider that issued the certificate.

**Business certificate (DigiCert, GeoTrust, ZeroSSL paid, Sectigo).** Bought with
your own account at the provider and paid there. The panel never sees a password
or card number: you connect the account with an API key once.
- DigiCert and GeoTrust (DigiCert CertCentral API key) and ZeroSSL paid (ZeroSSL API
  key): choose the product, years and domain check in the panel. The panel creates
  the private key and CSR, places the order, publishes the domain check file or DNS
  record, and installs the certificate as soon as the provider issues it. Orders are
  checked every 10 minutes, and **Check now** asks at once.
- An order placed on the provider's website can be imported by its order number.
- Sectigo sells through resellers, so the panel creates the key and CSR for you to
  paste at your Sectigo seller. Install the certificate you receive under
  **Own certificate**: the key made by the panel is matched automatically.
- VortexPanel has no direct or indirect relation with the buying or selling of SSL
  certificates. Orders, payments, refunds and support are between you and the
  provider.

**Own certificate.** Paste or upload the certificate, private key and CA chain, or a
.pfx/.p12 file with its password. **Check** shows, before anything changes, whether
the key matches, which domains are covered, the expiry date and whether the chain is
complete (missing intermediate certificates are fetched automatically). A
certificate that does not cover the website is refused.

**Switch back.** Installing a certificate keeps the previous one, and
**Switch back** restores it in one click.

**Safer validation.** The HTTPS redirect now leaves
`/.well-known/acme-challenge/` and `/.well-known/pki-validation/` on plain HTTP, so
renewals and provider domain checks keep working on sites that force HTTPS. Before
a file-check request, the panel checks that the website really answers the check
file and skips `www` when it has no DNS record, instead of failing at the CA.

## Upgrade

Panels on 3.11.1: **Settings > Update**.

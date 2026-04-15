# Authentication

The module supports two authentication modes: anonymous access (no credentials) and GSI/x509 proxy certificate authentication.

---

## Anonymous access

The default. Any client can connect and provide any username — no certificate or password is checked.

```nginx
stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data/public;
        # xrootd_auth none;  ← this is the default, no need to write it
    }
}
```

Use this for public data, internal networks, or when access control is handled at the network layer.

---

## GSI / x509 authentication

GSI (Grid Security Infrastructure) is the standard authentication method across the WLCG computing grid. It uses x509 proxy certificates — short-lived credentials derived from your long-term grid certificate.

If you are new to GSI: think of it like SSH keys, but with a certificate authority (your home institution or CERN) vouching for who you are, and the "proxy" certificate being a temporary 12-hour credential you generate each morning with `voms-proxy-init` or `grid-proxy-init`.

### What you need

On the **server**:
- A host certificate (`hostcert.pem`) issued by a trusted CA — typically from your institution's grid CA
- The corresponding private key (`hostkey.pem`)
- The CA certificate that signed the client certificates you want to accept (`ca.pem`)

On the **client**:
- A valid proxy certificate (generated from their personal grid certificate)

### Configuration

```nginx
stream {
    server {
        listen 1095;
        xrootd on;
        xrootd_auth gsi;
        xrootd_root /data/store;
        xrootd_certificate     /etc/grid-security/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/hostkey.pem;
        xrootd_trusted_ca      /etc/grid-security/ca.pem;
        xrootd_access_log /var/log/nginx/xrootd_gsi.log;
    }
}
```

The private key file must be readable by the nginx worker processes (typically running as `www-data` or `nginx`). The certificate and CA files can be world-readable.

### Testing GSI authentication

Generate a proxy certificate, then point `xrdcp` at it:

```bash
# Generate a proxy from your personal grid certificate
voms-proxy-init    # or: grid-proxy-init

# Tell xrdcp where the proxy lives (usually automatic, but explicit here)
export X509_USER_PROXY=$(voms-proxy-info -path)

# Copy a file
xrdcp /tmp/test.txt root://localhost:1095//test.txt
```

If authentication succeeds, the access log shows the client's subject DN:

```
192.168.1.1 gsi "/DC=org/OU=Users/CN=Alice Example" [14/Apr/2026:10:23:44 +0000] "AUTH - gsi" OK 0 48ms
```

### The authenticated identity

After a successful GSI handshake, the module extracts the subject Distinguished Name from the proxy certificate chain and stores it in the session. It appears in the access log and is available for any downstream logging. The module does not currently perform authorisation based on the DN — all authenticated clients are treated equally.

---

## How GSI authentication works (simplified)

If you do not care about the internals, skip this section.

The GSI handshake uses Diffie-Hellman key exchange to establish a shared session key, then the client sends their proxy certificate chain encrypted with that key. The server verifies the chain against its configured trusted CA.

```
Client                                       Server
──────                                       ──────
kXR_protocol (requests security info)  ─>
                                        <─  security requirements ("gsi" required)

kXR_login                              ─>
                                        <─  session ID + GSI challenge text
                                            "&P=gsi,v:10000,c:ssl,ca:<ca_hash>"

kXR_auth [step: "certreq"]             ─>   "here is a random nonce"
                                        <─  DH public key + server cert
                                            + server's signature of the nonce

kXR_auth [step: "cert"]                ─>   DH public key + proxy cert chain
                                            (AES-encrypted with DH session key)
                                        <─  auth complete (kXR_ok)
```

The proxy certificate is verified using standard OpenSSL chain verification (`X509_verify_cert`) with the `X509_V_FLAG_ALLOW_PROXY_CERTS` flag set to accept RFC 3820 proxy certificates.

---

## Using both anonymous and GSI on different ports

A common setup: public data on port 1094 (no credentials needed) and private or writable data on port 1095 (GSI required):

```nginx
stream {
    # Public read-only
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data/public;
    }

    # Authenticated read-write
    server {
        listen 1095;
        xrootd on;
        xrootd_auth gsi;
        xrootd_allow_write on;
        xrootd_root /data/restricted;
        xrootd_certificate     /etc/grid-security/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/hostkey.pem;
        xrootd_trusted_ca      /etc/grid-security/ca.pem;
    }
}
```

Clients use `root://host:1094//path` for public access and `root://host:1095//path` for authenticated access.

---

## TLS / encrypted transport

The module does not implement XRootD-level TLS (`kXR_haveTLS` / `roots://`). To encrypt the connection:

**Option 1: stunnel in front of nginx**

Run stunnel on port 1093 (or any port) that wraps the XRootD connection and forwards it to nginx on 1094.

**Option 2: nginx `ssl_preread` (layer-4 TLS termination)**

Add an nginx `stream` block with `ssl_preread on` that terminates TLS and proxies the inner TCP connection to the XRootD server block. Clients use `roots://` (XRootD's TLS scheme), which is just XRootD over TLS.

This is currently outside the scope of this module.

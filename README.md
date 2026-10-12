# Sample mTLS applications

Two separate Spring Boot applications demonstrate mutual TLS over a local HTTPS REST call:

- **Requester management UI:** <http://127.0.0.1:8081>
- **Responder management UI:** <http://127.0.0.1:8082>
- **Responder mTLS API:** <https://localhost:8443/api/hello>

The management pages bind only to loopback and use HTTP so they remain accessible before certificates have been configured. The responder API requires a trusted client certificate. The requester verifies the responder certificate and presents its own identity certificate.

For CA trust, rotation procedures, and production-readiness considerations, see [MTLS-recommendations.txt](./MTLS-recommendations.txt).

## Requirements

- JDK 21
- Maven 3.9+

## Generate demo credentials

The UI on either app provides **Generate a demo certificate bundle**. Download and extract the ZIP; it contains:

| File | Configure in |
| --- | --- |
| `requester.p12` | Requester identity store |
| `requester-truststore.p12` | Requester truststore |
| `responder.p12` | Responder identity store |
| `responder-truststore.p12` | Responder truststore |

The generated PKCS#12 password is `changeit`. For a command-line bundle, run:

```sh
bash scripts/generate-certificates.sh [output-directory] [password]
```

Certificates are self-signed, valid for 365 days, and have `localhost` and `127.0.0.1` subject alternative names. They are for local learning only, not production.

## Build and run

Build both apps:

```sh
mvn package
```

Run each application in a separate terminal:

```sh
java -jar requester/target/requester-1.0.0.jar
java -jar responder/target/responder-1.0.0.jar
```

In the responder UI, upload `responder.p12` and `responder-truststore.p12`, both with password `changeit`. In the requester UI, upload `requester.p12` and `requester-truststore.p12`. Once configured, use **Send mTLS request** on the requester page.

## Demonstrate certificate rotation

Generate a new bundle, then upload the replacement identity store and truststore to the respective app. A successful upload validates the full PKCS#12 material before applying it:

- The requester swaps its `HttpClient`/`SSLContext` immediately. Requests already in flight can finish using their existing client; subsequent requests use the new credentials.
- The responder starts a new HTTPS listener with the replacement `SSLContext` and then closes the old listener. The application process stays up, though an in-flight request can be interrupted during this short listener handoff.

Regenerating the complete bundle rotates both identities. Existing truststores from a different bundle do not trust the new self-signed certificates, so upload the matching new truststores as well. For a production-style rotation with overlap, use a CA truststore that contains both old and new issuers before switching the identity certificate.

Passwords are entered into the local UI and held only in application memory; uploaded credential bytes are not written to disk. Restarting an app clears its configuration, so re-upload the stores after a restart.

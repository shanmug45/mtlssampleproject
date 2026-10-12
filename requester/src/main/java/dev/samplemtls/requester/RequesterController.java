package dev.samplemtls.requester;

import dev.samplemtls.common.CertificateBundleArchive;
import dev.samplemtls.common.TlsContexts;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class RequesterController {
    private final AtomicReference<HttpClient> client = new AtomicReference<>();

    @GetMapping("/api/status")
    public Map<String, Object> status() {
        return Map.of("role", "requester", "credentialsConfigured", client.get() != null,
                "responderEndpoint", "https://localhost:8443/api/hello",
                "management", "http://127.0.0.1:8081");
    }

    @PostMapping(value = "/api/credentials", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> configure(@RequestParam("identityStore") MultipartFile identityStore,
                                            @RequestParam("identityPassword") String identityPassword,
                                            @RequestParam("trustStore") MultipartFile trustStore,
                                            @RequestParam("trustPassword") String trustPassword) {
        try {
            byte[] identity = identityStore.getBytes();
            byte[] trust = trustStore.getBytes();
            SSLContext sslContext = TlsContexts.create(identity, identityPassword.toCharArray(),
                    trust, trustPassword.toCharArray());
            HttpClient updated = HttpClient.newBuilder().sslContext(sslContext)
                    .connectTimeout(Duration.ofSeconds(5)).build();
            client.set(updated);
            return ResponseEntity.ok("Requester credentials applied.");
        } catch (IOException | GeneralSecurityException exception) {
            return ResponseEntity.badRequest()
                    .body("Could not apply PKCS#12 credentials: " + exception.getMessage());
        }
    }

    @PostMapping("/api/send")
    public ResponseEntity<String> send() {
        HttpClient current = client.get();
        if (current == null) {
            return ResponseEntity.badRequest().body("Upload the requester identity store and truststore first.");
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create("https://localhost:8443/api/hello"))
                    .timeout(Duration.ofSeconds(10)).POST(HttpRequest.BodyPublishers.noBody()).build();
            HttpResponse<String> response = current.send(request, HttpResponse.BodyHandlers.ofString());
            return ResponseEntity.status(response.statusCode()).body(response.body());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return ResponseEntity.internalServerError().body("Request interrupted: " + exception.getMessage());
        } catch (IOException exception) {
            return ResponseEntity.internalServerError().body(
                    "mTLS request failed: " + exception.getClass().getSimpleName() + ": " + exception.getMessage());
        }
    }

    @PostMapping("/api/certificates/generate")
    public ResponseEntity<byte[]> generate() throws IOException, InterruptedException {
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"sample-mtls-certificates.zip\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM).body(CertificateBundleArchive.create());
    }
}

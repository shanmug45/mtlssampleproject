package dev.samplemtls.responder;

import dev.samplemtls.common.CertificateBundleArchive;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class ResponderController {
    private final DynamicHttpsService httpsService;

    public ResponderController(DynamicHttpsService httpsService) {
        this.httpsService = httpsService;
    }

    @GetMapping("/api/status")
    public Map<String, Object> status() {
        return Map.of("role", "responder", "credentialsConfigured", httpsService.isRunning(),
                "mtlsEndpoint", "https://localhost:8443/api/hello",
                "management", "http://127.0.0.1:8082");
    }

    @PostMapping(value = "/api/credentials", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> configure(@RequestParam("identityStore") MultipartFile identityStore,
                                            @RequestParam("identityPassword") String identityPassword,
                                            @RequestParam("trustStore") MultipartFile trustStore,
                                            @RequestParam("trustPassword") String trustPassword) {
        try {
            httpsService.reload(identityStore.getBytes(), identityPassword.toCharArray(),
                    trustStore.getBytes(), trustPassword.toCharArray());
            return ResponseEntity.ok(
                    "Responder credentials applied; the HTTPS listener now uses the uploaded material.");
        } catch (IOException | GeneralSecurityException exception) {
            return ResponseEntity.badRequest()
                    .body("Could not apply responder credentials: " + exception.getMessage());
        }
    }

    @PostMapping("/api/certificates/generate")
    public ResponseEntity<byte[]> generate() throws IOException, InterruptedException {
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"sample-mtls-certificates.zip\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM).body(CertificateBundleArchive.create());
    }
}

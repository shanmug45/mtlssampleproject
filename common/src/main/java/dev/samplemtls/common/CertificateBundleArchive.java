package dev.samplemtls.common;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class CertificateBundleArchive {
    private CertificateBundleArchive() {
    }

    public static byte[] create() throws IOException, InterruptedException {
        Path directory = Files.createTempDirectory("sample-mtls-certs-");
        try {
            CertificateBundleGenerator.generate(directory, "changeit");
            Files.writeString(directory.resolve("README.txt"), """
                    Sample mTLS certificate bundle

                    PKCS#12 password for every .p12 file: changeit
                    requester.p12 + requester-truststore.p12 -> requester app
                    responder.p12 + responder-truststore.p12 -> responder app

                    Certificates are self-signed, valid for 365 days, and intended only for local learning.
                    """);
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (ZipOutputStream zip = new ZipOutputStream(bytes);
                 var files = Files.list(directory)) {
                for (Path file : files.toList()) {
                    zip.putNextEntry(new ZipEntry(file.getFileName().toString()));
                    Files.copy(file, zip);
                    zip.closeEntry();
                }
            }
            return bytes.toByteArray();
        } finally {
            try (var files = Files.list(directory)) {
                for (Path file : files.toList()) {
                    Files.deleteIfExists(file);
                }
            }
            Files.deleteIfExists(directory);
        }
    }
}

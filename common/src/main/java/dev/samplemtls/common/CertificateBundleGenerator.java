package dev.samplemtls.common;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class CertificateBundleGenerator {
    private CertificateBundleGenerator() {
    }

    public static void generate(Path outputDirectory, String password) throws IOException, InterruptedException {
        if (password.length() < 6) {
            throw new IllegalArgumentException("PKCS#12 password must contain at least 6 characters.");
        }
        Files.createDirectories(outputDirectory);
        Path requester = outputDirectory.resolve("requester.p12");
        Path responder = outputDirectory.resolve("responder.p12");
        Path requesterCert = outputDirectory.resolve("requester.cer");
        Path responderCert = outputDirectory.resolve("responder.cer");
        Path requesterTrust = outputDirectory.resolve("requester-truststore.p12");
        Path responderTrust = outputDirectory.resolve("responder-truststore.p12");

        for (Path generatedFile : List.of(requester, responder, requesterCert, responderCert,
                requesterTrust, responderTrust)) {
            Files.deleteIfExists(generatedFile);
        }

        run("-genkeypair", "-alias", "requester", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "365", "-dname", "CN=requester,OU=SampleMTLS,O=Learning",
                "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-storetype", "PKCS12",
                "-keystore", requester.toString(), "-storepass", password, "-keypass", password,
                "-noprompt");
        run("-genkeypair", "-alias", "responder", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "365", "-dname", "CN=localhost,OU=SampleMTLS,O=Learning",
                "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-storetype", "PKCS12",
                "-keystore", responder.toString(), "-storepass", password, "-keypass", password,
                "-noprompt");
        run("-exportcert", "-rfc", "-alias", "responder", "-keystore", responder.toString(),
                "-storepass", password, "-file", responderCert.toString());
        run("-exportcert", "-rfc", "-alias", "requester", "-keystore", requester.toString(),
                "-storepass", password, "-file", requesterCert.toString());
        run("-importcert", "-alias", "responder", "-file", responderCert.toString(),
                "-storetype", "PKCS12", "-keystore", requesterTrust.toString(),
                "-storepass", password, "-noprompt");
        run("-importcert", "-alias", "requester", "-file", requesterCert.toString(),
                "-storetype", "PKCS12", "-keystore", responderTrust.toString(),
                "-storepass", password, "-noprompt");
    }

    private static void run(String... arguments) throws IOException, InterruptedException {
        List<String> command = new java.util.ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
        command.addAll(List.of(arguments));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes());
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IOException("keytool failed (exit " + exitCode + "): " + output);
        }
    }

    public static void main(String[] args) throws Exception {
        Path output = args.length > 0 ? Path.of(args[0]) : Path.of("certificates");
        String password = args.length > 1 ? args[1] : "changeit";
        generate(output, password);
        System.out.println("Generated demo certificates in " + output.toAbsolutePath());
    }
}

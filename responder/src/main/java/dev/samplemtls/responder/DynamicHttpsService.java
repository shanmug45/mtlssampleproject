package dev.samplemtls.responder;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import dev.samplemtls.common.TlsContexts;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLContext;
import org.springframework.stereotype.Component;

@Component
public class DynamicHttpsService {
    private final ObjectMapper objectMapper;
    private HttpsServer server;
    private ExecutorService executor;
    private SSLContext activeContext;

    public DynamicHttpsService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public synchronized void reload(byte[] identity, char[] identityPassword,
                                    byte[] trust, char[] trustPassword)
            throws GeneralSecurityException, IOException {
        SSLContext context = TlsContexts.create(identity, identityPassword, trust, trustPassword);
        SSLContext previousContext = activeContext;
        stopListener();
        try {
            startListener(context);
        } catch (IOException | RuntimeException exception) {
            if (previousContext != null) {
                try {
                    startListener(previousContext);
                } catch (IOException | RuntimeException restoreException) {
                    exception.addSuppressed(restoreException);
                }
            }
            throw exception;
        }
    }

    private void startListener(SSLContext context) throws IOException {
        HttpsServer replacement = HttpsServer.create(new InetSocketAddress("127.0.0.1", 8443), 0);
        replacement.setHttpsConfigurator(new HttpsConfigurator(context) {
            @Override
            public void configure(com.sun.net.httpserver.HttpsParameters parameters) {
                var sslParameters = getSSLContext().getDefaultSSLParameters();
                sslParameters.setNeedClientAuth(true);
                parameters.setSSLParameters(sslParameters);
            }
        });
        replacement.createContext("/api/hello", exchange -> {
            byte[] response;
            int status;
            if (!"POST".equals(exchange.getRequestMethod())) {
                status = 405;
                response = "{\"error\":\"Use POST.\"}".getBytes(StandardCharsets.UTF_8);
            } else {
                status = 200;
                String peer = ((com.sun.net.httpserver.HttpsExchange) exchange)
                        .getSSLSession().getPeerPrincipal().getName();
                response = objectMapper.writeValueAsBytes(java.util.Map.of(
                        "message", "Hello from the responder over mutually authenticated TLS.",
                        "client", peer));
            }
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.sendResponseHeaders(status, response.length);
            try (var body = exchange.getResponseBody()) {
                body.write(response);
            }
        });
        ExecutorService replacementExecutor = Executors.newCachedThreadPool();
        replacement.setExecutor(replacementExecutor);
        try {
            replacement.start();
        } catch (RuntimeException exception) {
            replacementExecutor.shutdownNow();
            replacement.stop(0);
            throw exception;
        }
        server = replacement;
        executor = replacementExecutor;
        activeContext = context;
    }

    private void stopListener() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
        activeContext = null;
    }

    public synchronized boolean isRunning() {
        return server != null;
    }
}

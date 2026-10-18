package io.github.rmkrdev.entra.security.test.obo;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import com.sun.net.httpserver.HttpServer;

/**
 * A stand-in for the downstream API: {@code GET /token} answers with the bearer token it received, so tests can
 * inspect what the on-behalf-of exchange produced.
 */
final class DownstreamApi {

    private static final DownstreamApi SHARED = new DownstreamApi();

    private final HttpServer server;
    private final List<String> tokens = new CopyOnWriteArrayList<>();

    private DownstreamApi() {
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        }
        catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        server.createContext("/token", exchange -> {
            try (exchange) {
                String authorization = exchange.getRequestHeaders().getFirst("Authorization");
                String token = authorization != null && authorization.startsWith("Bearer ")
                        ? authorization.substring(7) : "";
                tokens.add(token);
                byte[] body = token.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "text/plain");
                exchange.sendResponseHeaders(token.isEmpty() ? 401 : 200, body.length == 0 ? -1 : body.length);
                if (body.length > 0) {
                    try (OutputStream out = exchange.getResponseBody()) {
                        out.write(body);
                    }
                }
            }
        });
        server.start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> server.stop(0)));
    }

    static DownstreamApi shared() {
        return SHARED;
    }

    String baseUrl() {
        return "http://" + server.getAddress().getHostString() + ":" + server.getAddress().getPort();
    }

    List<String> tokens() {
        return tokens;
    }
}

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class WebsiteMonitorApp {

    private static final List<TargetSite> SITES = List.of(
        new TargetSite("Google", "https://www.google.com"),
        new TargetSite("YouTube", "https://www.youtube.com"),
        new TargetSite("GitHub", "https://github.com"),
        new TargetSite("Stack Overflow", "https://stackoverflow.com"),
        new TargetSite("LinkedIn", "https://www.linkedin.com"),
        new TargetSite("Netflix", "https://www.netflix.com"),
        new TargetSite("Wikipedia", "https://www.wikipedia.org"),
        new TargetSite("Amazon", "https://www.amazon.com"),
        new TargetSite("Microsoft", "https://www.microsoft.com"),
        new TargetSite("Invalid Test Domain", "https://this-is-a-fake-domain-test12345.com")
    );

    private static final ExecutorService executor = Executors.newFixedThreadPool(10);
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .executor(executor)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public static void main(String[] args) throws IOException {
        int port = 8081;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        
        server.createContext("/api/status", new StatusHandler());
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor()); 
        
        System.out.println("🚀 Backend monitoring server started on http://localhost:8081/api/status");
        server.start();
    }

    static class TargetSite {
        String name;
        String url;

        TargetSite(String name, String url) {
            this.name = name;
            this.url = url;
        }
    }

    static class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // --- SECURITY GATE START ---
            // This verifies the frontend has the correct token before showing data
            String auth = exchange.getRequestHeaders().getFirst("X-Auth-Token");
            if (!"VIGILANT_SECURE_2026".equals(auth)) {
                exchange.sendResponseHeaders(401, -1); // 401 = Unauthorized
                return; // Stop the function here, do not run the rest of the code
            }
            // --- SECURITY GATE END ---

            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Content-Type", "application/json");

            if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                // ... (YOUR EXISTING 700+ LINES OF LOGIC CONTINUE HERE UNTOUCHED)
                List<CompletableFuture<String>> futures = SITES.stream()
                        .map(StatusHandler::checkSiteAsync)
                        .toList();

                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

                String jsonResponse = futures.stream()
                        .map(CompletableFuture::join)
                        .collect(Collectors.joining(",", "[", "]"));

                byte[] responseBytes = jsonResponse.getBytes();
                exchange.sendResponseHeaders(200, responseBytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(responseBytes);
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }

        private static CompletableFuture<String> checkSiteAsync(TargetSite site) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(site.url))
                    .GET()
                    .build();

            long startTime = System.currentTimeMillis();

            return httpClient.sendAsync(request, HttpResponse.BodyHandlers.discarding())
                    .thenApply(response -> {
                        long latency = System.currentTimeMillis() - startTime;
                        int status = response.statusCode();
                        String state = (status >= 200 && status < 400) ? "UP" : "DOWN";
                        return formatJson(site.name, site.url, state, latency, String.valueOf(status));
                    })
                    .exceptionally(ex -> {
                        long latency = System.currentTimeMillis() - startTime;
                        return formatJson(site.name, site.url, "DOWN", latency, "ERR");
                    });
        }

        private static String formatJson(String name, String url, String status, long latency, String code) {
            return String.format(
                "{\"name\":\"%s\",\"url\":\"%s\",\"status\":\"%s\",\"latency\":%d,\"code\":\"%s\"}",
                name, url, status, latency, code
            );
        }
    }
}
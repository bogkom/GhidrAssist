package ghidrassist.apiprovider;

import ghidrassist.apiprovider.exceptions.APIProviderException;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;

/** Real HTTP error mapping without network or credentials. */
public final class APIProviderDiagnosticsSelfTest {
    private static final class Provider extends OpenAIOAuthProvider {
        Provider() { super("diagnostic-test", "test-model", 100, "https://example.invalid/responses",
            "{\"access_token\":\"TOKEN_SENTINEL_PRIVATE\",\"account_id\":\"ACCOUNT_SENTINEL_PRIVATE\"}", false, true, 1); }
        APIProviderException error(String body) {
            Response response = new Response.Builder().request(new Request.Builder().url("https://example.invalid").build())
                .protocol(Protocol.HTTP_1_1).code(400).message("Bad Request").build();
            return handleHttpError(response, body, "createChatCompletionWithFunctionsFullResponse");
        }
    }
    public static void main(String[] args) {
        Provider provider = new Provider();
        APIProviderException error = provider.error("{\"error\":{\"message\":\"Invalid tools[19].name: fixture.get_task_status\",\"code\":\"invalid_value\"}}");
        if (error.getHttpStatusCode() != 400 || !"invalid_value".equals(error.getApiErrorCode())
            || !"Invalid tools[19].name: fixture.get_task_status".equals(error.getMessage()))
            throw new AssertionError("Lost HTTP status, API code or complete useful error message");
        if (!provider.error("{\"detail\":\"Unsupported option reasoning\"}").getMessage().contains("Unsupported option reasoning"))
            throw new AssertionError("Top-level detail was lost");
        String escaped = provider.error("{\"error\":{\"message\":\"Quoted \\\"name\\\" and newline\\nexplanation\"}}").getMessage();
        if (!escaped.contains("\"name\"") || !escaped.contains("\nexplanation")) throw new AssertionError("JSON escapes corrupted");
        String safe = provider.error("{\"error\":{\"message\":\"TOKEN_SENTINEL_PRIVATE ACCOUNT_SENTINEL_PRIVATE Bearer OTHER_SECRET session_id=PRIVATE_SESSION\"}}").getMessage();
        if (safe.contains("SENTINEL_PRIVATE") || safe.contains("OTHER_SECRET") || safe.contains("PRIVATE_SESSION"))
            throw new AssertionError("Credentials or session identifier leaked");
        if (provider.error("<html>Bearer PRIVATE_HTML</html>").getMessage().contains("PRIVATE_HTML"))
            throw new AssertionError("Raw unstructured error body leaked");
        if (provider.error("{}").getMessage().isBlank()) throw new AssertionError("Empty diagnostic fallback");
        System.out.println("APIProviderDiagnosticsSelfTest PASS");
    }
}

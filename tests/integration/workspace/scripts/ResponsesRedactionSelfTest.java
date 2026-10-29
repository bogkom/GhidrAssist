import com.google.gson.*;
import java.lang.reflect.*;

/** Offline privacy contract for the actual response observer; never calls a provider. */
public final class ResponsesRedactionSelfTest {
    public static void main(String[] args)throws Exception {
        Class<?> type=Class.forName("AgenticProbe$OAuthTelemetry");Constructor<?> constructor=type.getDeclaredConstructor();constructor.setAccessible(true);Object telemetry=constructor.newInstance();
        Method clean=type.getDeclaredMethod("diagnosticCopy",JsonElement.class);clean.setAccessible(true);
        JsonElement input=JsonParser.parseString("{\"run_id\":\"TEST_RUN\",\"session_id\":\"PRIVATE_SESSION\",\"usage\":{\"input_tokens\":12},\"output\":[{\"type\":\"reasoning\",\"encrypted_content\":\"PRIVATE_OPAQUE_REASONING\",\"summary\":[\"PRIVATE_REASONING\"]},{\"type\":\"function_call\",\"call_id\":\"PRIVATE_CALL\",\"name\":\"ga_get_document_page\",\"arguments\":\"{}\"}]}");
        input.getAsJsonObject().add("schema",JsonParser.parseString("{\"type\":[\"string\",\"null\"]}"));
        JsonObject result=((JsonElement)clean.invoke(telemetry,input)).getAsJsonObject();String serialized=result.toString();
        if(serialized.contains("PRIVATE_")||serialized.contains("encrypted_content")||serialized.contains("session_id")||serialized.contains("call_id"))throw new AssertionError("Opaque context or identifiers leaked");
        if(result.getAsJsonObject("usage").get("input_tokens").getAsInt()!=12||!serialized.contains("ga_get_document_page")||!serialized.contains("TEST_RUN"))throw new AssertionError("Useful diagnostic facts were lost");
        if(!result.getAsJsonObject("schema").get("type").isJsonArray())throw new AssertionError("Union schema corrupted");
        System.out.println("ResponsesRedactionSelfTest PASS");
    }
}

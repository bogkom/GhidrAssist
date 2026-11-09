package ghidrassist.automation;

import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import java.util.regex.Pattern;

/**
 * Only canonical wire-format identities can authorize stitching two read-only
 * pages. Gson getAsLong/getAsInt silently coerces JSON strings, fractions,
 * exponents and numbers outside the target range; none are valid receipts.
 */
final class AutomationRpcPagination {
    private AutomationRpcPagination(){}
    private static final Pattern DECIMAL=Pattern.compile("(0|[1-9][0-9]{0,18})");
    private static final Pattern UUID=Pattern.compile(
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    static Long optionalRevision(JsonObject args,String field){
        if(!args.has(field))return null;
        JsonPrimitive primitive;
        try {
            primitive=args.get(field).getAsJsonPrimitive();
        }catch(RuntimeException invalid){
            throw new IllegalArgumentException("Invalid expected revision: "+field,invalid);
        }
        if(!primitive.isNumber() || !DECIMAL.matcher(primitive.getAsString()).matches())
            throw new IllegalArgumentException(
                "Expected revision must be canonical JSON nonnegative integer: "+field);
        try {
            return Long.parseLong(primitive.getAsString());
        }catch(NumberFormatException invalid){
            throw new IllegalArgumentException("Expected revision out of range: "+field,invalid);
        }
    }

    static String optionalUuid(JsonObject args,String field){
        if(!args.has(field))return null;
        JsonPrimitive primitive;
        try { primitive=args.get(field).getAsJsonPrimitive(); }
        catch(RuntimeException invalid){
            throw new IllegalArgumentException("Invalid generation/run identity: "+field,invalid);
        }
        if(!primitive.isString() || !UUID.matcher(primitive.getAsString()).matches())
            throw new IllegalArgumentException("Expected UUID identity required: "+field);
        return primitive.getAsString();
    }

    static void requiredAfterFirst(int offset,Long revision,
            String identity,String name) {
        if(offset>0 && (revision==null ||
                (identity!=null && identity.isBlank())))
            throw new IllegalArgumentException(
                "Nonzero "+name+" offset requires exact Program revision");
    }

    static void requiredAfterFirst(int offset,Long revision,
            Long pageRevision,String generation,String name) {
        if(offset>0 && (revision==null || pageRevision==null ||
                generation==null))
            throw new IllegalArgumentException(
                "Nonzero "+name+" offset requires Program revision, evidence revision and run");
    }
}

package ghidrassist.hardware;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Unambiguous, bounded GA-12 full-input fingerprint field encoding.
 * No Ghidra dependency so source identity safety is tested with Java 21.
 */
final class HardwareInputFingerprintFields {
    private HardwareInputFingerprintFields(){}

    private static void integer(MessageDigest digest,int number){
        digest.update((byte)(number>>>24));
        digest.update((byte)(number>>>16));
        digest.update((byte)(number>>>8));
        digest.update((byte)number);
    }

    /** -1 encodes absent data, never a user/source literal such as "<null>". */
    static void string(MessageDigest digest,String value){
        if(digest==null)throw new IllegalArgumentException("Missing digest");
        if(value==null){
            integer(digest,-1);
            return;
        }
        byte[] bytes=value.getBytes(StandardCharsets.UTF_8);
        integer(digest,bytes.length);
        digest.update(bytes);
    }

    /** Record exact body topology, including holes without instructions. */
    static void functionRange(MessageDigest digest,String start,String end){
        if(digest==null || start==null || end==null)
            throw new IllegalArgumentException("Missing function range");
        digest.update((byte)'R');
        string(digest,start);
        string(digest,end);
    }

    /** Terminate the range list even if it is empty; never merge adjacent bodies. */
    static void endFunctionRanges(MessageDigest digest,int count){
        if(digest==null || count<0 || count>1_000_000)
            throw new IllegalArgumentException("Invalid function range count");
        digest.update((byte)'E');
        integer(digest,count);
    }
}

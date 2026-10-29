package ghidrassist.hardware;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;

/**
 * Explicit, local, read-only confirmation of a user-supplied PDF checksum.
 * Matching bytes do not verify the claimed manual edition, page locations,
 * register definitions, reset conditions or MCU identity.
 */
public final class HardwareProfilePdfHashCheck {
    private HardwareProfilePdfHashCheck() {}
    public static final long MAX_PDF_BYTES=128L*1024*1024;

    public enum Status { MATCH, MISMATCH, CLAIM_UNKNOWN, INVALID_PDF, TOO_LARGE }
    public record Result(Status status,String claimedSha256,String computedSha256,long bytes) {
        public String report(){
            StringBuilder out=new StringBuilder();
            out.append("Local PDF SHA-256 result: ").append(status).append("\n");
            if(computedSha256!=null)
                out.append("Computed SHA-256: ").append(computedSha256).append("\n");
            out.append("Bytes checked: ").append(bytes).append("\n");
            out.append("This verifies only an equality against the manifest's ")
               .append("CLAIMED digest (when MATCH). It does NOT validate the ")
               .append("manual edition, physical PDF-page labels, MCU identity, ")
               .append("bitfields or reset values.\n")
               .append("No document imported, indexed, uploaded or written to Ghidra.\n");
            return out.toString();
        }
    }

    /** Streaming, bounded: never loads full PDF contents in memory. */
    public static Result verify(InputStream stream,String expectedSha256,long maxBytes)
            throws IOException {
        if(stream==null || maxBytes<5 || maxBytes>MAX_PDF_BYTES)
            throw new IllegalArgumentException("Invalid input stream or byte limit");
        if(expectedSha256==null ||
                "UNKNOWN".equalsIgnoreCase(expectedSha256))
            return new Result(Status.CLAIM_UNKNOWN,expectedSha256,null,0);
        if(!expectedSha256.matches("[a-fA-F0-9]{64}"))
            throw new IllegalArgumentException("Malformed claimed PDF SHA-256");
        try {
            MessageDigest digest=MessageDigest.getInstance("SHA-256");
            byte[] buffer=new byte[8192],header=new byte[5];
            int headerCount=0;
            long count=0;
            int len;
            while((len=stream.read(buffer))!=-1){
                if(len==0) {
                    int one=stream.read();
                    if(one==-1)break;
                    buffer[0]=(byte)one;
                    len=1;
                }
                if(count+len>maxBytes)
                    return new Result(Status.TOO_LARGE,expectedSha256,null,count+len);
                for(int i=0;i<len && headerCount<5;i++)
                    header[headerCount++]=buffer[i];
                digest.update(buffer,0,len);
                count+=len;
            }
            if(headerCount!=5 || header[0]!='%' || header[1]!='P' ||
                    header[2]!='D' || header[3]!='F' || header[4]!='-')
                return new Result(Status.INVALID_PDF,expectedSha256,null,count);
            String actual=HexFormat.of().formatHex(digest.digest());
            return new Result(actual.equals(expectedSha256.toLowerCase(Locale.ROOT)) ?
                Status.MATCH:Status.MISMATCH,expectedSha256,actual,count);
        }catch(NoSuchAlgorithmException impossible){
            throw new IllegalStateException("SHA-256 missing from Java runtime",impossible);
        }
    }
}

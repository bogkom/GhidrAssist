package ghidrassist.hardware;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * GA-08/13: exact function/ordinal/storage receipts for explicitly approved
 * pointer variable renames. Stored in the SAME Ghidra Program transaction as
 * the name edit, never in a user profile, external file or remote service.
 * SHA-256 protects against accidental corruption, NOT hostile edits or
 * authenticates a human/model actor. Native Undo can remove the record.
 */
public final class HardwareScopedVariableReceipt {
    private HardwareScopedVariableReceipt() {}
    public static final String OPTIONS_CATEGORY="GhidrAssist Pointer Variable Rename Receipts";
    public static final String VERSION="GA13-POINTER-VARIABLE-1";
    public static final int MAX_BYTES=3072;
    public static final int MAX_ROWS=4096;

    public record Entry(long function,
            HardwareScopedVariableReview.Kind kind,int ordinal,String storage,
            String beforeName,String afterName,long reviewedModification,
            String importSha256) {
        public Entry {
            if(function<0 || function>0xffffffL || kind==null ||
                    ordinal<0 || ordinal>1024 ||
                    storage==null || storage.isBlank() || storage.length()>256 ||
                    beforeName==null || beforeName.isBlank() ||
                    beforeName.length()>256 ||
                    afterName==null || afterName.isBlank() ||
                    afterName.length()>128 || reviewedModification<0 ||
                    importSha256==null || importSha256.isBlank() ||
                    importSha256.length()>128)
                throw new IllegalArgumentException("Invalid variable rename receipt");
        }
        public String optionKey(){return HardwareScopedVariableReceipt.optionKey(
            function,kind,ordinal);}
        public String origin(){
            return "GhidrAssist explicit pointer variable approval; actor UNKNOWN";
        }
    }
    public static String optionKey(long function,
            HardwareScopedVariableReview.Kind kind,int ordinal) {
        if(function<0 || function>0xffffffL || kind==null ||
                ordinal<0 || ordinal>1024)
            throw new IllegalArgumentException("Variable key outside MCU24 scope");
        return String.format(Locale.ROOT,"PV_%08X_%s_%04d",
            function,kind==HardwareScopedVariableReview.Kind.PARAMETER?"P":"L",
            ordinal);
    }
    private static String encoded(String source) {
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(source.getBytes(StandardCharsets.UTF_8));
    }
    private static String decoded(String base64){
        byte[] bytes=Base64.getUrlDecoder().decode(base64);
        String value=new String(bytes,StandardCharsets.UTF_8);
        if(!java.util.Arrays.equals(bytes,value.getBytes(StandardCharsets.UTF_8)))
            throw new IllegalArgumentException("Noncanonical UTF-8 in stored receipt");
        return value;
    }
    private static String checksum(String text) {
        try{
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(text.getBytes(StandardCharsets.UTF_8)));
        }catch(NoSuchAlgorithmException impossible){
            throw new IllegalStateException("SHA-256 unavailable",impossible);
        }
    }
    public static String encode(Entry receipt) {
        if(receipt==null)throw new IllegalArgumentException("Null variable receipt");
        String source=String.join("\t",VERSION,receipt.optionKey(),
            Integer.toString(receipt.ordinal()),encoded(receipt.storage()),
            encoded(receipt.beforeName()),encoded(receipt.afterName()),
            Long.toString(receipt.reviewedModification()),
            encoded(receipt.importSha256()));
        String payload=source+"\t"+checksum(source);
        if(payload.getBytes(StandardCharsets.UTF_8).length>MAX_BYTES)
            throw new IllegalArgumentException("Oversized variable receipt");
        return payload;
    }
    public static Entry decode(String encodedReceipt) {
        if(encodedReceipt==null || encodedReceipt.isEmpty() ||
                encodedReceipt.getBytes(StandardCharsets.UTF_8).length>MAX_BYTES)
            throw new IllegalArgumentException("Missing/oversized variable receipt");
        String[] p=encodedReceipt.split("\t",-1);
        if(p.length!=9 || !VERSION.equals(p[0]) ||
                !p[1].matches("PV_[0-9A-F]{8}_[PL]_[0-9]{4}") ||
                !p[8].matches("[0-9a-f]{64}"))
            throw new IllegalArgumentException("Unsupported variable receipt version");
        String source=encodedReceipt.substring(0,encodedReceipt.lastIndexOf('\t'));
        if(!MessageDigest.isEqual(checksum(source).getBytes(StandardCharsets.US_ASCII),
                p[8].getBytes(StandardCharsets.US_ASCII)))
            throw new IllegalArgumentException("Variable receipt checksum mismatch");
        try {
            String[] key=p[1].split("_");
            long function=Long.parseLong(key[1],16);
            var kind="P".equals(key[2])?
                HardwareScopedVariableReview.Kind.PARAMETER:
                HardwareScopedVariableReview.Kind.LOCAL;
            var entry=new Entry(function,kind,Integer.parseInt(p[2]),
                decoded(p[3]),decoded(p[4]),decoded(p[5]),
                Long.parseLong(p[6]),decoded(p[7]));
            if(!entry.optionKey().equals(p[1]) ||
                    !encode(entry).equals(encodedReceipt))
                throw new IllegalArgumentException("Noncanonical variable receipt");
            return entry;
        }catch(IllegalArgumentException invalid){
            throw new IllegalArgumentException("Invalid persisted variable receipt",invalid);
        }
    }

    public enum State {
        CURRENT_APPROVED_NAME, NAME_CHANGED_AFTER_APPROVAL,
        VARIABLE_MISSING, STORAGE_CHANGED, TYPE_OR_SOURCE_CHANGED,
        SOURCE_CHANGED, SOURCE_UNVERIFIED
    }
    /** One decoded stored record correlated with the *current* live Variable. */
    public record Observation(String optionKey,String serialized,
            String liveName,String liveStorage,
            boolean pointerType,boolean userDefined) {
        public Observation {
            if(optionKey==null || serialized==null ||
                    optionKey.length()>64 ||
                    (liveName!=null && liveName.length()>512) ||
                    (liveStorage!=null && liveStorage.length()>512))
                throw new IllegalArgumentException("Invalid variable audit observation");
        }
    }
    public record Row(Entry receipt,String currentName,
                      String currentStorage,State state) {
        public Row {
            if(receipt==null || state==null)
                throw new IllegalArgumentException("Malformed variable audit row");
        }
    }
    public record Snapshot(List<Row> rows,long revision,String sourceSha256) {
        public Snapshot {
            if(rows==null || rows.size()>MAX_ROWS || revision<0 ||
                    sourceSha256==null || sourceSha256.length()>128)
                throw new IllegalArgumentException("Unbounded variable audit snapshot");
            rows=List.copyOf(rows);
        }
        public long count(State state){
            return rows.stream().filter(r->r.state()==state).count();
        }
        public String csv() {
            StringBuilder b=new StringBuilder(
                "function,kind,ordinal,storage,before_name,approved_name,"+
                "current_name,current_storage,reviewed_revision,program_revision,"+
                "reviewed_sha256,current_sha256,state,operation_origin\n");
            for(var row:rows) {
                var r=row.receipt();
                List<String> values=List.of(r.optionKey(),r.kind().name(),
                    Integer.toString(r.ordinal()),r.storage(),r.beforeName(),
                    r.afterName(),row.currentName()==null?
                        "(variable missing)":row.currentName(),
                    row.currentStorage()==null?"UNKNOWN":row.currentStorage(),
                    Long.toString(r.reviewedModification()),Long.toString(revision),
                    r.importSha256(),sourceSha256,row.state().name(),r.origin());
                if(b.length()>64_000_000)
                    throw new IllegalStateException("Unbounded variable receipt CSV");
                for(int i=0;i<values.size();i++) {
                    if(i>0)b.append(',');
                    b.append(HardwareChangeProvenance.cell(values.get(i)));
                }
                b.append('\n');
            }
            return b.toString();
        }
        public String csvRevisionBound(HardwareAnalysisRevision captured,
                Supplier<HardwareAnalysisRevision> current) {
            if(captured==null || current==null ||
                    captured.modificationNumber()!=revision ||
                    !Objects.equals(captured.sourceSha256(),sourceSha256))
                throw new IllegalArgumentException("Wrong variable audit revision fence");
            if(!captured.same(current.get()))
                throw new IllegalStateException("STALE_REVISION variable receipt audit");
            String rendered=csv();
            if(!captured.same(current.get()))
                throw new IllegalStateException("STALE_REVISION during variable receipt CSV");
            return rendered;
        }
    }
    /** Pure policy: a current name is never trusted without exact storage,
     * pointer type, source type, matching import checksum and the receipt. */
    public static Snapshot inspect(List<Observation> observations,long revision,
                                   String importSha256) {
        if(observations==null || observations.size()>MAX_ROWS || revision<0 ||
                importSha256==null || importSha256.length()>128)
            throw new IllegalArgumentException("Unbounded variable receipt inventory");
        Set<String> keys=new HashSet<>();
        List<Row> rows=new ArrayList<>();
        for(var observed:observations) {
            if(observed==null || !keys.add(observed.optionKey()))
                throw new IllegalArgumentException("Duplicate/null variable receipt key");
            Entry record=decode(observed.serialized());
            if(!record.optionKey().equals(observed.optionKey()))
                throw new IllegalArgumentException("Variable receipt option key mismatch");
            State state;
            if(observed.liveName()==null)state=State.VARIABLE_MISSING;
            // Syntax is a necessary gate for a current approval claim.
            // Matching non-hex legacy source labels are never trusted as
            // a verified binary identity. This does not authenticate bytes.
            else if(!HardwareAnalysisRevision.isVerifiableExecutableSha256(
                        record.importSha256()) ||
                    !HardwareAnalysisRevision.isVerifiableExecutableSha256(
                        importSha256))
                state=State.SOURCE_UNVERIFIED;
            else if(!record.importSha256().equalsIgnoreCase(importSha256))
                state=State.SOURCE_CHANGED;
            else if(!Objects.equals(record.storage(),observed.liveStorage()))
                state=State.STORAGE_CHANGED;
            else if(!observed.pointerType() || !observed.userDefined())
                state=State.TYPE_OR_SOURCE_CHANGED;
            else if(!record.afterName().equals(observed.liveName()))
                state=State.NAME_CHANGED_AFTER_APPROVAL;
            else state=State.CURRENT_APPROVED_NAME;
            rows.add(new Row(record,observed.liveName(),observed.liveStorage(),state));
        }
        rows.sort(Comparator.comparingLong((Row r)->r.receipt().function())
            .thenComparing(r->r.receipt().kind())
            .thenComparingInt(r->r.receipt().ordinal()));
        return new Snapshot(rows,revision,importSha256);
    }
}

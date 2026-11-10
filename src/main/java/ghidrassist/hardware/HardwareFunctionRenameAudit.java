package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/**
 * GA-13: read-only, revision-snapshot audit of existing transactional
 * function-rename receipts and their current Ghidra symbol state.
 *
 * This does NOT create an append-only Undo log, authenticate a human/AI
 * actor or invent history erased by Ghidra Undo. Missing/malformed data
 * fails closed rather than being reported as approved.
 */
public final class HardwareFunctionRenameAudit {
    private HardwareFunctionRenameAudit() {}

    public static final int MAX_ROWS=4096;

    public enum State {
        CURRENT_APPROVED_NAME, NAME_CHANGED_AFTER_APPROVAL,
        FUNCTION_MISSING, SOURCE_CHANGED, SOURCE_UNVERIFIED, SOURCE_TYPE_CHANGED
    }

    /** One stored Options value and the corresponding live Function lookup. */
    public record Observation(String optionKey,String serialized,
            String currentName,String sourceType) {
        public Observation {
            if(optionKey==null || serialized==null ||
                    optionKey.length()>64 ||
                    (currentName!=null && currentName.length()>512) ||
                    (sourceType!=null && sourceType.length()>64))
                throw new IllegalArgumentException("Malformed rename audit observation");
        }
    }

    public record Row(HardwareFunctionRenameReceipt.Entry receipt,
                      String currentName,String sourceType,State state) {
        public Row {
            if(receipt==null || sourceType==null || state==null)
                throw new IllegalArgumentException("Incomplete rename audit row");
        }
        public String origin() { return receipt.operationOrigin(); }
    }

    public record Snapshot(List<Row> rows,long programRevision,
                           String programSourceSha256) {
        public Snapshot {
            if(rows==null || rows.size()>MAX_ROWS || programRevision<0 ||
                    programSourceSha256==null || programSourceSha256.length()>128)
                throw new IllegalArgumentException("Invalid audit snapshot");
            rows=List.copyOf(rows);
        }
        /** CSV is an evidence export, never instructions for Apply. */
        public String csv() {
            StringBuilder b=new StringBuilder(
                "function_entry,before_name,approved_name,current_name,"+
                "reviewed_modification,program_modification,import_sha256,"+
                "current_import_sha256,role,register_evidence,write_sites,"+
                "ghidra_source_type,audit_state,operation_origin\n");
            for(Row r:rows) {
                var e=r.receipt();
                List<String> cells=List.of(
                        HardwareFunctionRenameReceipt.optionKey(e.entry()),
                        e.beforeName(),e.afterName(),
                        r.currentName()==null?"(function missing)":r.currentName(),
                        Long.toString(e.reviewedModification()),
                        Long.toString(programRevision),e.sourceSha256(),
                        programSourceSha256,e.role(),e.registers(),
                        Integer.toString(e.writeSites()),r.sourceType(),
                        r.state().name(),r.origin());
                for(int col=0;col<cells.size();col++) {
                    if(b.length()>64_000_000)
                        throw new IllegalStateException("Unbounded audit CSV");
                    if(col>0)b.append(',');
                    b.append(HardwareChangeProvenance.cell(cells.get(col)));
                }
                b.append('\n');
            }
            return b.toString();
        }
        /**
         * A saved read-only Options audit must never be exported as CURRENT
         * after an intervening Ghidra edit/Undo/Redo or Program switch.
         * A process-local modification token cannot be persisted across JVMs.
         *
         * Fail closed before and after CSV assembly: one stale row must not
         * leak as a partially built export. The caller supplies a fresh
         * Program-bound revision snapshot each time.
         */
        public String csvRevisionBound(HardwareAnalysisRevision captured,
                Supplier<HardwareAnalysisRevision> current) {
            if(captured==null || current==null ||
                    captured.modificationNumber()!=programRevision ||
                    !java.util.Objects.equals(captured.sourceSha256(),
                        programSourceSha256))
                throw new IllegalArgumentException(
                    "Rename audit export has no matching revision fence");
            if(!captured.same(current.get()))
                throw new IllegalStateException(
                    "STALE_REVISION: rename audit CSV no longer current");
            String payload=csv();
            if(!captured.same(current.get()))
                throw new IllegalStateException(
                    "STALE_REVISION: rename audit changed during CSV export");
            return payload;
        }

        public long count(State state) {
            return rows.stream().filter(r->r.state()==state).count();
        }
    }

    /**
     * Decode and correlate only saved Options belonging to GA-13.
     * No guessed default actor, no silently ignored malformed option,
     * no replacement for the current live Function source classification.
     */
    public static Snapshot inspect(List<Observation> observations,
            long programRevision,String programSourceSha256) {
        if(observations==null || observations.size()>MAX_ROWS ||
                programRevision<0 || programSourceSha256==null || programSourceSha256.length()>128)
            throw new IllegalArgumentException("Unbounded rename audit inventory");
        List<Row> rows=new ArrayList<>(observations.size());
        Set<String> keys=new HashSet<>();
        for(Observation observation:observations) {
            if(observation==null || !keys.add(observation.optionKey()))
                throw new IllegalArgumentException("Null/duplicate rename audit key");
            var receipt=HardwareFunctionRenameReceipt.decode(observation.serialized());
            if(!HardwareFunctionRenameReceipt.optionKey(receipt.entry())
                    .equals(observation.optionKey()))
                throw new IllegalArgumentException("Receipt key/entry mismatch");
            String name=observation.currentName();
            String type=observation.sourceType()==null?"UNKNOWN":observation.sourceType();
            State state;
            if(name==null)state=State.FUNCTION_MISSING;
            // Legacy/current arbitrary matching labels (including lowercase
            // "unknown" and 64 non-hex characters) are NOT proof of an
            // executable SHA-256. Keep old receipts readable but unverified.
            else if(!HardwareAnalysisRevision.isVerifiableExecutableSha256(
                        receipt.sourceSha256()) ||
                    !HardwareAnalysisRevision.isVerifiableExecutableSha256(
                        programSourceSha256))
                state=State.SOURCE_UNVERIFIED;
            else if(!receipt.sourceSha256().equalsIgnoreCase(programSourceSha256))
                state=State.SOURCE_CHANGED;
            else if(!name.equals(receipt.afterName()))
                state=State.NAME_CHANGED_AFTER_APPROVAL;
            else if(!"USER_DEFINED".equals(type))
                state=State.SOURCE_TYPE_CHANGED;
            else state=State.CURRENT_APPROVED_NAME;
            rows.add(new Row(receipt,name,type,state));
        }
        rows.sort(Comparator.comparingLong(row->row.receipt().entry()));
        return new Snapshot(rows,programRevision,programSourceSha256);
    }
}

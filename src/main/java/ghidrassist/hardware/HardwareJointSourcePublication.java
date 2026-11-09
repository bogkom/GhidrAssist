package ghidrassist.hardware;

import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

/**
 * GA-12/18: atomic read-only source-report publication against the exact
 * in-memory Program revision and stage-invalidation epoch.
 *
 * A stale analysis must not publish any partial JSR, MOVEC, RESET or MMIO
 * source location, nor can a prior completed stage be replayed after clear.
 * This is an input-consistency fence, not proof of runtime execution.
 */
public final class HardwareJointSourcePublication {
    private HardwareJointSourcePublication() {}

    public static final class StaleRevision extends IllegalStateException {
        public StaleRevision() { super("STALE_REVISION"); }
    }

    public static void requireCurrent(HardwareAnalysisRevision captured,
            Supplier<HardwareAnalysisRevision> current,
            BooleanSupplier stageCurrent) {
        if(captured==null || current==null || stageCurrent==null ||
                !stageCurrent.getAsBoolean())
            throw new StaleRevision();
        HardwareAnalysisRevision latest=current.get();
        if(!captured.same(latest) || !stageCurrent.getAsBoolean())
            throw new StaleRevision();
    }

    /** Never expose the rendered body on either an entry or exit race. */
    public static String render(HardwareAnalysisRevision captured,
            Supplier<HardwareAnalysisRevision> current,
            BooleanSupplier stageCurrent,Supplier<String> renderer) {
        if(renderer==null)throw new IllegalArgumentException("Missing renderer");
        requireCurrent(captured,current,stageCurrent);
        String body=renderer.get();
        requireCurrent(captured,current,stageCurrent);
        if(body==null)throw new IllegalArgumentException("Missing report");
        return body;
    }
}

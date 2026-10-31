package ghidrassist.hardware;

import java.util.Objects;

/**
 * Schema-tagged completed-stage evidence. This is deliberately not a
 * persistent disk checkpoint and never asserts that a partially executed
 * stage can be resumed. Identity is provided by an external weak-key map.
 */
public final class HardwareStageCheckpoint<T> {
    public static final String SCHEMA="GA12-STAGE-1";
    public static final String CFG_STAGE="CFG_PCODE_COMPLETE";
    private final String schema,stage,language,sourceSha;
    private final long modification;
    private final boolean mc68332;
    private final T evidence;

    private HardwareStageCheckpoint(String schema,String stage,long modification,
            String language,String sourceSha,boolean mc68332,T evidence) {
        if(!SCHEMA.equals(schema) || !CFG_STAGE.equals(stage) ||
                modification<0 || language==null || language.isBlank() ||
                evidence==null)throw new IllegalArgumentException("Invalid completed stage");
        this.schema=schema;this.stage=stage;this.modification=modification;
        this.language=language;this.sourceSha=sourceSha;
        this.mc68332=mc68332;this.evidence=evidence;
    }

    public static <T> HardwareStageCheckpoint<T> complete(
            long modification,String language,String sourceSha,boolean mc68332,T evidence) {
        return new HardwareStageCheckpoint<>(SCHEMA,CFG_STAGE,modification,
            language,sourceSha,mc68332,evidence);
    }

    public boolean validFor(long currentModification,String currentLanguage,
            String currentSha,boolean selectedMc68332) {
        return SCHEMA.equals(schema) && CFG_STAGE.equals(stage) &&
            modification==currentModification && language.equals(currentLanguage) &&
            Objects.equals(sourceSha,currentSha) && mc68332==selectedMc68332;
    }

    public T evidence(){return evidence;}
    public String stage(){return stage;}
    public String schema(){return schema;}
}

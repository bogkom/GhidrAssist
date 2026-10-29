package ghidrassist.hardware;

import java.util.Objects;

/**
 * Process-local, immutable analysis input revision. The original executable
 * SHA-256 is Ghidra metadata, NOT a hash of later program analysis edits.
 * Ghidra's monotonically changed DomainObject modification number guards
 * analysis actions, undo and redo; object identity stops cross-project reuse.
 *
 * This is a foundation for future stage checkpoints. It does NOT persist
 * progress across Ghidra restarts or claim a resumable CFG implementation.
 */
public final class HardwareAnalysisRevision {
    public static final String ALGORITHM="GA12-REV1";
    private final Object identity;
    private final long modificationNumber;
    private final String language;
    private final String sourceSha256;
    private final boolean mc68332Selected;

    private HardwareAnalysisRevision(Object identity,long modificationNumber,
            String language,String sourceSha256,boolean mc68332Selected) {
        if(identity==null || modificationNumber<0 || language==null ||
                language.isBlank())
            throw new IllegalArgumentException("Invalid Ghidra input revision");
        this.identity=identity;
        this.modificationNumber=modificationNumber;
        this.language=language;
        this.sourceSha256=sourceSha256;
        this.mc68332Selected=mc68332Selected;
    }

    public static HardwareAnalysisRevision capture(Object identity,long modificationNumber,
            String language,String originalExecutableSha256,boolean mc68332Selected) {
        return new HardwareAnalysisRevision(identity,modificationNumber,language,
            originalExecutableSha256,mc68332Selected);
    }

    public long modificationNumber() { return modificationNumber; }
    public String language() { return language; }
    public String sourceSha256() { return sourceSha256; }
    public boolean mc68332Selected() { return mc68332Selected; }

    /**
     * Strict same-in-memory-program and same analysis input revision.
     * Never accept another Program object even if its name/hash are identical.
     */
    public boolean matches(Object currentProgram,long currentModification,
            String currentLanguage,String currentExecutableSha,
            boolean selectedMc68332) {
        return identity==currentProgram &&
            modificationNumber==currentModification &&
            language.equals(currentLanguage) &&
            Objects.equals(sourceSha256,currentExecutableSha) &&
            mc68332Selected==selectedMc68332;
    }

    public boolean same(HardwareAnalysisRevision candidate) {
        return candidate!=null &&
            matches(candidate.identity,candidate.modificationNumber,
                candidate.language,candidate.sourceSha256,candidate.mc68332Selected);
    }
}

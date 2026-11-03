package ghidrassist.hardware;

/**
 * A user-approved function rename must refer to the same Ghidra analysis
 * snapshot even across a modal confirmation. SourceType is not authorship.
 */
public final class HardwareFunctionRenameRevisionGate {
    private HardwareFunctionRenameRevisionGate(){}
    public static void requireCurrent(HardwareAnalysisRevision approved,
            Object program,long modificationNumber,String language,
            String originalExecutableSha,boolean mc68332Selected) {
        if(approved==null || !mc68332Selected || !approved.mc68332Selected() ||
                !approved.matches(program,modificationNumber,language,
                    originalExecutableSha,mc68332Selected))
            throw new IllegalStateException(
                "Function rename approval is stale; rerun Analyze");
    }
}

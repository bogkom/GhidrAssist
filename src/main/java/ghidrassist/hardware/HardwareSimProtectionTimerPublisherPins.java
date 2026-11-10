package ghidrassist.hardware;

import java.util.Map;

/**
 * GA-06/10/16: frozen, independently computed official-publisher excerpt
 * SHA-256 fingerprints from MC68332UM Motorola 1995 D-10/D-11.
 *
 * References were produced by GitHub Actions run 42816712499 on the
 * SHA-pinned publisher's ORIGINAL 265-page NXP PDF, then checked against
 * reviewed field positions and text on physical PDF 224/225.
 * A matching excerpt/filenamed index alone is NOT independent proof
 * of local PDF bytes, edited index content or MCU runtime. Do not
 * update these pins automatically if publisher source changes.
 */
public final class HardwareSimProtectionTimerPublisherPins {
    private HardwareSimProtectionTimerPublisherPins(){}
    private static final Map<String,String> KNOWN=Map.ofEntries(
        Map.entry("SYPCR/SWE","a9e2edb11761adcf0dfe7bd9ac891a0cea9e7cd60ffcc39d87aa74a20be444a4"),
        Map.entry("SYPCR/SWP","0214033cf38b92874e6a8d925f3cbca790fcabd76596e51e5b9b470274a89fca"),
        Map.entry("SYPCR/SWT","caa993fd4f66a6f02758dfd50e6ee29434f44b5573b616378e66674380aeaa52"),
        Map.entry("SYPCR/HME","2a06524653cf67e68524e9dca575ec6de3606043059be5bde0b437222b81bc11"),
        Map.entry("SYPCR/BME","287fa4fed83dbddee852bc1da6de044c130943b9ad00bafe530cce2ba4374d72"),
        Map.entry("SYPCR/BMT","4bcc048472da34c677de2fa074948105de648155458795c1ade57fb331a8ff17"),
        Map.entry("PICR/PIRQL","f87cc6ad573bbb4cacfa7a8dd4292ec1cd76966463c69b60a4b3d6b1dda9afe6"),
        Map.entry("PICR/PIV","c3119c45b9e5bb7484167510ccb7e478ac42c2b898195468bbae48dca2ec5c2a"),
        Map.entry("PITR/PTP","5f4023d1724430e54c61d2f98540a6ad0d8a37770aed7544c677d7be260fdb9d"),
        Map.entry("PITR/PITM","a42b491321cc76c10ac0a36f67775bbe9dd428f0df5643fc295cf0e238b036b8")
    );
    public static String expected(String register,String field) {
        return register==null || field==null?null:
            KNOWN.get(register+"/"+field);
    }
    public static boolean matches(HardwareSimProtectionTimerWitness.Row row){
        if(row==null || row.state()!=
                HardwareSimProtectionTimerWitness.State.MATCHED_TEXT_CANDIDATE)
            return false;
        String pinned=expected(row.reviewed().register(),
            row.reviewed().field());
        return pinned!=null && pinned.equals(row.excerptSha256());
    }
    public static int matches(HardwareSimProtectionTimerWitness.Report report) {
        if(report==null)return 0;
        return (int)report.rows().stream()
            .filter(HardwareSimProtectionTimerPublisherPins::matches).count();
    }
    /** Pure frozen-source text comparison, not PDF-file authentication. */
    public static boolean allTenMatch(HardwareSimProtectionTimerWitness.Report report) {
        return report!=null && report.allTenCandidatesMatch() &&
            report.rows().size()==KNOWN.size() &&
            matches(report)==KNOWN.size();
    }
}

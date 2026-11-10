package ghidrassist.hardware;

import java.util.Map;

/**
 * GA-06/10/16 frozen SOURCE-EXCERPT SHA-256 references.
 *
 * Independently observed on CI's publisher-hosted 265-page MC68332UM PDF
 * with its SHA-256 validated BEFORE pdftotext -layout extraction of exact
 * physical PDF pages 219, 220, 221 (Motorola 1995, Appendix D-5/D-6/D-7).
 * Do not auto-update after a changed PDF or use these hashes as evidence
 * that arbitrary local/RAG text, edition or actual MCU runtime is verified.
 */
public final class HardwareManualPublisherExcerptPins {
    private HardwareManualPublisherExcerptPins(){}
    private static final Map<String,String> KNOWN=Map.ofEntries(
        Map.entry("SIMCR/EXOFF","532a498cd9f0ca5e471fa28d99379fdf29d27ac9ffa4eff50c9f669829344c67"),
        Map.entry("SIMCR/FRZSW","b751f5f217c873ec7dfc3edd4636cc058cef9bdcaec28c7487e3d8a8528e15f3"),
        Map.entry("SIMCR/FRZBM","4ce86a36a66faa354c264e31b189c7089b72475a421c47b8df201b74b9021996"),
        Map.entry("SIMCR/SLVEN","c67c8a390729eef1fabd63f95f03601a86057bfc8fe5e3b8960ba3f6822b8861"),
        Map.entry("SIMCR/SHEN","6e989c0d7ce4be35326091e1e384d0d6f080aff63970910c2fe035b1446e2a23"),
        Map.entry("SIMCR/SUPV","76ff0fd013e3a2609e5bb230f4ff939f8a1aeea29efa03e86e54d39eefa3bb99"),
        Map.entry("SIMCR/MM","0d85fbf8ae12643295cb108d9d03369bc019ecb43cf4b99e43dc78685ecd19fd"),
        Map.entry("SIMCR/IARB","841e699f66aecb3e6671073151afcf5bcbececfaf982e19d1aeb693b35f7777b"),
        Map.entry("SYNCR/W","356e172ee714ac362feab05e754e86cac2e08663b7b6f096834d878b2e4c59de"),
        Map.entry("SYNCR/X","eef74978d8b6371e56b3c644a95c23719cc318508866382862cd0ecd81cd5155"),
        Map.entry("SYNCR/Y","72156e747d35db558634c37e14e38a55684f92c73cc8a2d8c8920a3c27e0525c"),
        Map.entry("SYNCR/EDIV","7159903b836047309c88074e6c9f05b94b090e9cb94ffffcf6f5073d49798d20"),
        Map.entry("SYNCR/RSTEN","f57f30593222e3e415931c28a674a4c5166a4317be5243b3768afb16c958b628"),
        Map.entry("SYNCR/STSIM","ae494ffdc40cdf156430afe8f616d00703945588cf253cb2611783b70f9d4838"),
        Map.entry("SYNCR/STEXT","58cda3733855e618fc1cfa3a1737e45dd5f81e57fa5cb67b45a5e4a97770e3f1")
    );

    public static String expected(String register,String field){
        if(register==null || field==null)return null;
        return KNOWN.get(register+"/"+field);
    }
    public static boolean matches(
            HardwareManualFieldExcerptEvidence.Citation candidate) {
        if(candidate==null ||
                candidate.state()!=HardwareManualFieldExcerptEvidence.State
                    .MATCHED_TEXT_CANDIDATE)
            return false;
        return candidate.excerptSha256()!=null &&
            candidate.excerptSha256().equals(
                expected(candidate.reviewed().register(),
                    candidate.reviewed().field()));
    }
    public static int countMatches(
            HardwareManualFieldExcerptEvidence.Report report) {
        if(report==null)return 0;
        return (int)report.citations().stream()
            .filter(HardwareManualPublisherExcerptPins::matches).count();
    }
    /** Pure content comparison, NOT independent authentication of PDF bytes. */
    public static boolean allPinnedExcerptsMatch(
            HardwareManualFieldExcerptEvidence.Report report) {
        return report!=null && report.allReviewedTextCandidatesMatch() &&
            report.citations().size()==KNOWN.size() &&
            countMatches(report)==KNOWN.size();
    }
}

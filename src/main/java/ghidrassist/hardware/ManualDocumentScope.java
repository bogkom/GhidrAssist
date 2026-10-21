package ghidrassist.hardware;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Filename-scoped hints for vendor manuals. These are NOT MCU identification
 * and never authorize register import, auto-renaming or MM mapping.
 *
 * Unknown/renamed PDFs deliberately retain UNKNOWN scope. The RAG index stores
 * the original source filename, file hash and 1-based PDF page separately.
 */
public final class ManualDocumentScope {
    private ManualDocumentScope() {}
    private static final Pattern SPLIT_336=Pattern.compile(
        "^MC68336376UM(0[1-9]|1[0-3]|[ABCD]|TOC|LOF|LOT|IX|COVER)\\.PDF$");
    public record Identity(String documentId,String applicableModels,
            String editionPart,String confidence) {
        public String evidence(int pdfPage) {
            if(pdfPage<1)throw new IllegalArgumentException("Page must be 1-based");
            return "[RAG_SOURCE_METADATA document_id="+documentId+
                " models="+applicableModels+" part="+editionPart+
                " pdf_page="+pdfPage+
                " identity="+confidence+"; SOURCE IS NOT PROCESSOR PROOF]";
        }
    }
    public static Identity fromFilename(String name) {
        if(name==null || name.isBlank())
            return new Identity("UNKNOWN","UNKNOWN","UNKNOWN","UNVERIFIED_FILENAME");
        String upper=name.toUpperCase(Locale.ROOT);
        String base=upper.replaceAll("(?i)^.*[/\\\\]","");
        if(base.equals("MC68332UM.PDF"))
            return known("MC68332UM","MC68332","FULL_MANUAL");
        if(base.equals("MC68331UM.PDF"))
            return known("MC68331UM","MC68331","FULL_MANUAL");
        if(base.equals("MC68336376UM.PDF"))
            return known("MC68336376UM","MC68336+MC68376","FULL_MANUAL");
        Matcher split=SPLIT_336.matcher(base);
        if(split.matches()) {
            String part=split.group(1);
            return known("MC68336376UM"+part,"MC68336+MC68376",
                "SPLIT_"+part);
        }
        if(base.equals("MC68332TS.PDF"))
            return known("MC68332TS","MC68332","TECHNICAL_SUMMARY");
        if(base.equals("MC68331TS.PDF"))
            return known("MC68331TS","MC68331","TECHNICAL_SUMMARY");
        if(base.equals("M68000PRM.PDF"))
            return known("M68000PRM","M68K+CPU32","INSTRUCTION_REFERENCE");
        if(base.equals("CPU32RM.PDF"))
            return known("CPU32RM","CPU32_FAMILY","ARCHITECTURE_REFERENCE");
        if(base.equals("SIMRM.PDF"))
            return known("SIMRM","M683XX_VARIANT_DEPENDENT","MODULE_REFERENCE");
        if(base.equals("TPURM.PDF"))
            return known("TPURM","M683XX_VARIANT_DEPENDENT","MODULE_REFERENCE");
        if(base.equals("QSMRM.PDF"))
            return known("QSMRM","M683XX_VARIANT_DEPENDENT","MODULE_REFERENCE");
        return new Identity("UNKNOWN","UNKNOWN","UNKNOWN","UNVERIFIED_FILENAME");
    }
    private static Identity known(String id,String models,String part) {
        return new Identity(id,models,part,
            "FILENAME_MATCH_ONLY; VERIFY_COVER_AND_REVISION");
    }
}

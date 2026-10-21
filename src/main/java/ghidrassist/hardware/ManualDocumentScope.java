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
    private static final Pattern LOCAL_331 = Pattern.compile(
        "^MC(?:68331|331)_([A-Z0-9_-]{2,48})\\.PDF$");
    private static final Pattern LOCAL_332 = Pattern.compile(
        "^MC68332_([A-Z0-9_-]{2,48})\\.PDF$");
    private static final Pattern LOCAL_336 = Pattern.compile(
        "^MC68336_68376_(0[1-9]|1[0-3]|[ABCD])_([A-Z0-9_-]{2,48})\\.PDF$");
    private static final Pattern LEGACY_CHAPTER=Pattern.compile(
        "^C(0?[1-9]|1[0-3])([A-Z][A-Z0-9_-]{1,32})\\.PDF$");
    private static final Pattern LEGACY_APPENDIX=Pattern.compile(
        "^AP([A-D])([A-Z][A-Z0-9_-]{1,32})\\.PDF$");
    private static final Pattern MODEL_HEADER=Pattern.compile(
        "(?is)(MC68336\\s*/\\s*376|MC68331|MC68332|MC68375)" +
        "[^\\n\\r]{0,100}(?:\\R[^\\n\\r]{0,70})?" +
        "USER['’]S\\s+MANUAL");

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
        Matcher local331=LOCAL_331.matcher(base);
        if(local331.matches())
            return alias("MC68331_LOCAL_"+local331.group(1),"MC68331",
                "LOCAL_"+local331.group(1));
        Matcher local332=LOCAL_332.matcher(base);
        if(local332.matches())
            return alias("MC68332_LOCAL_"+local332.group(1),"MC68332",
                "LOCAL_"+local332.group(1));
        Matcher local336=LOCAL_336.matcher(base);
        if(local336.matches()) {
            String part=local336.group(1), module=local336.group(2);
            return alias("MC68336376UM"+part,
                part.equals("13")?"MC68376":"MC68336+MC68376",
                "SPLIT_"+part+"_"+module);
        }
        if(base.matches("MC68375_[A-Z0-9_-]{2,48}\\.PDF"))
            return new Identity("MC68375_LOCAL_UNVERIFIED","MC68375",
                "DEVICE_DOCUMENT_UNVERIFIED",
                "LOCAL_FILENAME_ALIAS; NO_PRIMARY_MANUAL_VERIFIED");
        if(base.equals("MC68332UM.PDF"))
            return known("MC68332UM","MC68332","FULL_MANUAL");
        if(base.equals("MC68331UM.PDF"))
            return known("MC68331UM","MC68331","FULL_MANUAL");
        if(base.equals("MC68336376UM.PDF"))
            return known("MC68336376UM","MC68336+MC68376","FULL_MANUAL");
        Matcher split=SPLIT_336.matcher(base);
        if(split.matches()) {
            String part=split.group(1);
            return known("MC68336376UM"+part,
                part.equals("13")?"MC68376":"MC68336+MC68376",
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
    /** Only strict "MC683xx USER'S MANUAL" page-header proximity is used.
     * Free text mentioning another MCU in the body never identifies the PDF.
     */
    public static Identity fromDocumentEvidence(String filename,String extractedPage) {
        Identity named=fromFilename(filename);
        String normalized=extractedPage==null?"":extractedPage
            .replace('’','\'').toUpperCase(Locale.ROOT);
        Matcher header=MODEL_HEADER.matcher(normalized);
        String headerModel=null;
        while(header.find()) {
            String observed=header.group(1).replaceAll("\\s+","")
                .toUpperCase(Locale.ROOT);
            observed=observed.equals("MC68336/376")?
                "MC68336+MC68376":observed;
            if(headerModel!=null && !headerModel.equals(observed))
                return new Identity("UNKNOWN","UNKNOWN","UNKNOWN",
                    "AMBIGUOUS_DOCUMENT_HEADERS");
            headerModel=observed;
        }
        if(headerModel==null)return named;
        // A chapter with TouCAN may be restricted to the MC68376, although
        // its shared book's header explicitly lists both 336 and 376.
        boolean compatible=named.applicableModels.equals(headerModel) ||
            named.applicableModels.equals("MC68376") &&
                headerModel.equals("MC68336+MC68376");
        if(!named.documentId.equals("UNKNOWN")) {
            if(!compatible && !named.applicableModels.equals("M683XX_VARIANT_DEPENDENT"))
                return new Identity("UNKNOWN","UNKNOWN","UNKNOWN",
                    "FILENAME_HEADER_MODEL_CONFLICT");
            if(named.applicableModels.equals("M683XX_VARIANT_DEPENDENT"))
                return named;
            return new Identity(named.documentId,named.applicableModels,
                named.editionPart,"FILENAME_AND_PDF_HEADER_AGREE; VERIFY_REVISION");
        }
        String base=filename==null?"":filename.toUpperCase(Locale.ROOT)
            .replaceAll("^.*[/\\\\]","");
        Matcher appendix=LEGACY_APPENDIX.matcher(base);
        if(appendix.matches()){
            String part=appendix.group(1);
            return new Identity("PDF_HEADER_"+headerModel+"_APPENDIX_"+part,
                headerModel,"SPLIT_"+part,
                "PDF_HEADER_MATCH; ARCHIVE_FILENAME_NOT_UNIQUE");
        }
        Matcher legacy=LEGACY_CHAPTER.matcher(base);
        if(legacy.matches()){
            String chapter=legacy.group(1);
            String part=String.format(Locale.ROOT,"%02d",Integer.parseInt(chapter));
            if(base.equals("C8QADC.PDF") &&
                    !headerModel.equals("MC68336+MC68376"))
                return new Identity("UNKNOWN","UNKNOWN","UNKNOWN",
                    "CHAPTER_MODULE_INCOMPATIBLE_WITH_HEADER");
            // Bare archive names such as c5sim.pdf are ambiguous: the same
            // basename is used in more than one NXP MCU archive.
            return new Identity("PDF_HEADER_"+headerModel+"_C"+part,
                headerModel,"SPLIT_"+part,
                "PDF_HEADER_MATCH; ARCHIVE_FILENAME_NOT_UNIQUE");
        }
        return named;
    }

    private static Identity alias(String id,String models,String part) {
        return new Identity(id,models,part,
            "LOCAL_FILENAME_ALIAS; VERIFY_PDF_HEADER_AND_REVISION");
    }

    private static Identity known(String id,String models,String part) {
        return new Identity(id,models,part,
            "FILENAME_MATCH_ONLY; VERIFY_COVER_AND_REVISION");
    }
}

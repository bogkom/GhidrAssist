package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Source-only evidence stream, intentionally NOT compatible with Apply CSV. */
public final class HardwareConfigurationEvidenceCsv {
    private HardwareConfigurationEvidenceCsv(){}
    public static final int MAX_ROWS=5000;
    public static final String HEADER="record_type,function,source_pc,register_candidate,address_candidate,"+
        "access,width_bits,word_literal_candidate,prior_simcr_candidate,mm_literal_bit,"+
        "other_pc,graph_relation,unknown_alias_or_flow,interpretation\n";
    public static final int MAX_CSV_CELL_CHARS=512;
    private static final String CELL_TRUNCATION=" [SOURCE_TRUNCATED]";
    /** 
     * Source-site register labels may originate from untrusted imported
     * symbols. Quoting CSV alone does not stop spreadsheet formula parsing.
     * Apply the same bounded Unicode Cf-aware escape policy as the read-only
     * function/register Review CSV; no result authorizes a Program edit.
     */
    private static String cell(String value){
        if(value==null)value="";
        if(value.length()>MAX_CSV_CELL_CHARS) {
            int cut=MAX_CSV_CELL_CHARS-CELL_TRUNCATION.length();
            // Never clip between UTF-16 halves of one code point.
            if(Character.isHighSurrogate(value.charAt(cut-1)) &&
                    Character.isLowSurrogate(value.charAt(cut)))cut--;
            value=value.substring(0,cut)+CELL_TRUNCATION;
        }
        String normalized=value.replace("\r"," ").replace("\n"," ")
            .replace("\u0000"," ").replace("\u2028"," ")
            .replace("\u2029"," ");
        int pos=0;
        while(pos<normalized.length()){
            int cp=normalized.codePointAt(pos);
            if(!Character.isWhitespace(cp) &&
                    !Character.isSpaceChar(cp) &&
                    Character.getType(cp)!=Character.FORMAT)break;
            pos+=Character.charCount(cp);
        }
        if(pos<normalized.length() &&
                "=+-@".indexOf(normalized.charAt(pos))>=0)
            normalized="'"+normalized;
        else if(normalized.startsWith("\t"))
            normalized="'"+normalized;
        return "\""+normalized.replace("\"","\"\"")+"\"";
    }
    private static String hex(long value){
        return String.format(Locale.ROOT,"0x%08X",value);
    }
    private static String row(String... values){
        if(values.length!=14)throw new IllegalArgumentException("Invalid CSV evidence schema");
        List<String> parts=new ArrayList<>(values.length);
        for(String value:values)parts.add(cell(value));
        return String.join(",",parts)+"\n";
    }
    /**
     * The upstream CSV is an untrusted interchange boundary. Validate the
     * exact 14-column quoted schema before appending a second evidence view:
     * a header prefix alone must not license forged or malformed rows.
     */
    // CSV quoting alone does not neutralize spreadsheet formulas.
    private static void requireSafeSourceCell(String value) {
        int pos=0;
        while(pos<value.length()) {
            int cp=value.codePointAt(pos);
            if(!Character.isWhitespace(cp) && !Character.isSpaceChar(cp) &&
                    Character.getType(cp)!=Character.FORMAT)break;
            pos+=Character.charCount(cp);
        }
        if((pos<value.length() && "=+-@".indexOf(value.charAt(pos))>=0) ||
                value.startsWith("\t"))
            throw new IllegalArgumentException("Unescaped formula in source CSV cell");
    }
    private static int validatedSourceRows(String rawCsv) {
        if(rawCsv==null || !rawCsv.startsWith(HEADER))
            throw new IllegalArgumentException("Untrusted source CSV header");
        int rows=0, start=HEADER.length();
        // A syntactically valid row must not impersonate a merged view or
        // smuggle an omission marker into the middle of the source stream.
        // Source serialization emits STORE*, CFG_PATH*, [OMITTED_ROWS].
        int phase=0;
        if(start==rawCsv.length())return 0;
        if(rawCsv.charAt(rawCsv.length()-1)!='\n')
            throw new IllegalArgumentException("Unterminated source CSV row");
        while(start<rawCsv.length()) {
            int fields=0;
            int i=start;
            StringBuilder kind=new StringBuilder();
            while(true) {
                if(i>=rawCsv.length() || rawCsv.charAt(i++)!='"')
                    throw new IllegalArgumentException("Unquoted source CSV cell");
                boolean closed=false;
                int decodedChars=0;
                StringBuilder decoded=new StringBuilder();
                while(i<rawCsv.length()) {
                    char c=rawCsv.charAt(i++);
                    if(c=='\r')throw new IllegalArgumentException("CR in source CSV");
                    if(c=='\n')throw new IllegalArgumentException("Embedded CSV newline");
                    if(c=='"') {
                        if(i<rawCsv.length() && rawCsv.charAt(i)=='"')i++;
                        else {closed=true;break;}
                    }
                    // Serialized cells are clipped to 512 UTF-16 units; the
                    // formula-neutralizing apostrophe may add one more.
                    // Do not let forged upstream rows bypass that budget.
                    decoded.append(c);
                    if(fields==0)kind.append(c);
                    if(++decodedChars>MAX_CSV_CELL_CHARS+1)
                        throw new IllegalArgumentException("Oversized source CSV cell");
                }
                if(!closed)throw new IllegalArgumentException("Open source CSV quote");
                requireSafeSourceCell(decoded.toString());
                fields++;
                if(i>=rawCsv.length())
                    throw new IllegalArgumentException("Unterminated source CSV row");
                char separator=rawCsv.charAt(i++);
                if(separator=='\n')break;
                if(separator!=',')
                    throw new IllegalArgumentException("Invalid source CSV separator");
            }
            if(fields!=14)throw new IllegalArgumentException("Wrong source CSV column count");
            String recordType=kind.toString();
            if("STORE".equals(recordType)) {
                if(phase!=0)throw new IllegalArgumentException("Out-of-order source STORE");
            } else if("CFG_PATH".equals(recordType)) {
                if(phase>1)throw new IllegalArgumentException("Out-of-order source CFG_PATH");
                phase=1;
            } else if("OMITTED_ROWS".equals(recordType)) {
                if(phase==2)throw new IllegalArgumentException("Duplicate source omission marker");
                phase=2;
            } else {
                throw new IllegalArgumentException("Untrusted source CSV record type");
            }
            if(++rows>MAX_ROWS)throw new IllegalArgumentException("Source CSV row budget exceeded");
            start=i;
        }
        return rows;
    }

    /**
     * Append normalized, deduplicated sources without deleting the raw CFG
     * provenance rows. MERGED_SITE rows are a second VIEW of the same PCs,
     * not additional executed stores. Strict cap keeps exports bounded.
     */
    public static String withUnifiedSources(String rawCsv,
            HardwareStartupEvidenceMerge.Report merged,boolean selectedMc68332) {
        if(merged==null)throw new IllegalArgumentException("Missing merged evidence");
        int rows=validatedSourceRows(rawCsv);
        StringBuilder out=new StringBuilder(rawCsv);
        int totalExtra=merged.rows().size()+(merged.unboundAliasStores()>0?1:0);
        int available=MAX_ROWS-rows;
        if(totalExtra>available && available==0)
            throw new IllegalArgumentException("No room for CSV omission marker");
        int omitted=0;
        for(HardwareStartupEvidenceMerge.Row s:merged.rows()){
            if(rows>=MAX_ROWS-(totalExtra>available?1:0)){omitted++;continue;}
            String names= (s.sources().contains(
                HardwareStartupEvidenceMerge.Source.LISTING_REFERENCE)?"LISTING_REF":"")+
                (s.sources().contains(HardwareStartupEvidenceMerge.Source.CFG_PCODE)?
                    (s.sources().size()>1?"+CFG_PCODE":"CFG_PCODE"):"");
            Integer bit=selectedMc68332 && s.candidateRegister().equals("SIMCR") &&
                s.status()==HardwareStartupEvidenceMerge.Status.FULL_WORD_LITERAL_CANDIDATE ?
                ((s.literalWord()&0x40)!=0?1:0):null;
            out.append(row("MERGED_SITE",hex(s.function()),hex(s.pc()),
                selectedMc68332?s.candidateRegister():"UNVERIFIED_MCU_REGISTER",
                hex(s.registerAddress()),names,
                s.widthBits()==0?"UNKNOWN":Integer.toString(s.widthBits()),
                s.status()==HardwareStartupEvidenceMerge.Status.FULL_WORD_LITERAL_CANDIDATE?
                    String.format(Locale.ROOT,"0x%04X",s.literalWord()):"UNKNOWN",
                "UNKNOWN",bit==null?"UNKNOWN":bit+" (STATIC_LITERAL_ONLY)",
                "",s.status().name(),
                Boolean.toString(s.conditionalOrUncertain() ||
                    merged.unboundAliasStores()>0),
                "RECONCILED_READ_ONLY_NEVER_AUTO_APPLY"));
            rows++;
        }
        if(merged.unboundAliasStores()>0) {
            if(rows<MAX_ROWS-(totalExtra>available?1:0)) {
                out.append(row("UNBOUND_ALIAS_SUMMARY","","",
                    selectedMc68332?"UNKNOWN_TARGET":"UNVERIFIED_MCU_REGISTER",
                    "UNKNOWN","CFG_PCODE","UNKNOWN","UNKNOWN","UNKNOWN",
                    "UNKNOWN","","UNBOUND_ALIAS_COUNT="+merged.unboundAliasStores(),
                    "true","POSSIBLE_ANY_MMIO_NEVER_AUTO_APPLY"));
                rows++;
            } else omitted++;
        }
        if(omitted>0)out.append(row("OMITTED_MERGED_SITES","","","","",
            "","","","","","",
            Integer.toString(omitted),"true","INCOMPLETE_EXPORT_NEVER_AUTO_APPLY"));
        return out.toString();
    }

    public static String serialize(HardwareCfgWriteAudit.Report stores,
            List<HardwareCfgStorePaths.Pair> paths,boolean mc68332Selected){
        if(stores==null || paths==null)
            throw new IllegalArgumentException("Evidence missing");
        StringBuilder out=new StringBuilder(HEADER);
        // Reserve the omission marker only if evidence actually exceeds
        // the budget; exactly MAX_ROWS rows must remain lossless.
        long requested=(long)stores.sites().size()+paths.size();
        int detailBudget=requested>MAX_ROWS?MAX_ROWS-1:MAX_ROWS;
        int emitted=0,omitted=0;
        for(HardwareCfgWriteAudit.Finding s:stores.sites()){
            if(emitted>=detailBudget){omitted++;continue;}
            out.append(row("STORE",hex(s.function()),hex(s.pc()),
                mc68332Selected?s.register():"UNVERIFIED_MCU_REGISTER",
                s.address()<0?"UNKNOWN":hex(s.address()),
                s.indirect()?"INDIRECT":"DIRECT",
                s.widthBits()==0?"UNKNOWN":Integer.toString(s.widthBits()),
                s.fullWordLiteral()?String.format(Locale.ROOT,"0x%04X",s.literal()):"UNKNOWN",
                s.simcrPrefix().name(),mc68332Selected && s.mmLiteralBit()!=null?
                    s.mmLiteralBit()+" (STATIC_LITERAL_ONLY)":"UNKNOWN",
                "","",Boolean.toString(s.mayAliasAnyMmio()),
                "READ_ONLY_STATIC_CANDIDATE_NEVER_AUTO_APPLY"));
            emitted++;
        }
        for(HardwareCfgStorePaths.Pair p:paths){
            if(p==null)throw new IllegalArgumentException("Null path");
            if(emitted>=detailBudget){omitted++;continue;}
            out.append(row("CFG_PATH",hex(p.function()),hex(p.aPc()),
                mc68332Selected?p.aRegister():"UNVERIFIED_MCU_REGISTER",
                "UNKNOWN","MODELED_CFG","UNKNOWN","UNKNOWN","UNKNOWN",
                "UNKNOWN",hex(p.bPc()),p.relation().name(),
                Boolean.toString(p.unknownFunctionControlFlow()),
                "READ_ONLY_POSSIBLE_PATH_NEVER_AUTO_APPLY"));
            emitted++;
        }
        if(omitted>0)out.append(row("OMITTED_ROWS","","","","","","","","","","",
            Integer.toString(omitted),"true","INCOMPLETE_EXPORT_NEVER_AUTO_APPLY"));
        return out.toString();
    }
}

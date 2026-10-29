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
    private static String cell(String value){
        if(value==null)value="";
        value=value.replace("\r"," ").replace("\n"," ").replace("\u0000"," ");
        // Spreadsheet files must not evaluate imported symbol names as formulas.
        if(!value.isEmpty() && "=+-@\t".indexOf(value.charAt(0))>=0)value="'"+value;
        return "\""+value.replace("\"","\"\"")+"\"";
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
    public static String serialize(HardwareCfgWriteAudit.Report stores,
            List<HardwareCfgStorePaths.Pair> paths,boolean mc68332Selected){
        if(stores==null || paths==null)
            throw new IllegalArgumentException("Evidence missing");
        StringBuilder out=new StringBuilder(HEADER);
        int emitted=0,omitted=0;
        for(HardwareCfgWriteAudit.Finding s:stores.sites()){
            if(emitted>=MAX_ROWS){omitted++;continue;}
            out.append(row("STORE",hex(s.function()),hex(s.pc()),
                mc68332Selected?s.register():"UNVERIFIED_MCU_REGISTER",
                s.address()<0?"UNKNOWN":hex(s.address()),
                s.indirect()?"INDIRECT":"DIRECT",Integer.toString(s.widthBits()),
                s.fullWordLiteral()?String.format(Locale.ROOT,"0x%04X",s.literal()):"UNKNOWN",
                s.simcrPrefix().name(),mc68332Selected && s.mmLiteralBit()!=null?
                    s.mmLiteralBit()+" (STATIC_LITERAL_ONLY)":"UNKNOWN",
                "","",Boolean.toString(s.mayAliasAnyMmio()),
                "READ_ONLY_STATIC_CANDIDATE_NEVER_AUTO_APPLY"));
            emitted++;
        }
        for(HardwareCfgStorePaths.Pair p:paths){
            if(p==null)throw new IllegalArgumentException("Null path");
            if(emitted>=MAX_ROWS){omitted++;continue;}
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

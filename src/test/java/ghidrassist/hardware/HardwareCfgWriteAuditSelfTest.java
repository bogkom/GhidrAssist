package ghidrassist.hardware;

import java.util.List;

public final class HardwareCfgWriteAuditSelfTest {
    private HardwareCfgWriteAuditSelfTest(){}
    private static void ok(boolean pass,String message){
        if(!pass)throw new AssertionError(message);
    }
    private static HardwareCfgWriteAudit.Site site(long pc,String name,long addr,
            boolean indirect,int bits,Integer word,int min,int max,
            boolean call,boolean unknownStore,boolean limited){
        return new HardwareCfgWriteAudit.Site(0x2bc0,pc,name,addr,indirect,bits,
            word,min,max,call,unknownStore,limited);
    }
    public static void main(String[] args) {
        var list=List.of(
            site(0x2bca,"SIMCR",0xfffa00,false,16,0x40ca,0,0,false,false,false),
            site(0x2bcc,"SIMCR",0xfffa00,true,16,0x4848,0,1,false,false,false),
            site(0x2bd0,"SIMCR",0xfffa00,true,16,null,1,2,false,false,false),
            site(0x2bd2,"CSBAR0",0xfffa4c,true,8,null,0,0,true,false,false),
            site(0x2bd4,"CSOR0",0xfffa4e,false,32,null,0,0,false,true,false),
            site(0x2bd6,"UNRESOLVED_ALIAS",-1,true,16,null,0,0,false,true,true));
        var report=HardwareCfgWriteAudit.inspect(true,list);
        ok(report.sites().size()==6 && report.fullWordLiterals()==2 &&
            report.partialOrUnresolvedWrites()==4 &&
            report.indirectStores()==4 && report.unresolvedAliases()==1 &&
            report.analysisIncomplete(),"distinct static evidence categories");
        ok(report.sites().get(0).simcrPrefix()==
            HardwareCfgWriteAudit.PriorSimcr.NO_MATCH_IN_MODELED_FUNCTION_PREFIX,
            "no prior function-local site is not a reset latch");
        ok(report.sites().get(0).mmLiteralBit()==1 &&
            report.sites().get(1).mmLiteralBit()==1 &&
            report.sites().get(2).mmLiteralBit()==null,
            "known 16-bit MM literal only");
        ok(report.sites().get(1).simcrPrefix()==
            HardwareCfgWriteAudit.PriorSimcr.POSSIBLE_MATCH_ON_SOME_CFG_PATHS,
            "branch-alternative predecessor cannot be marked definite");
        ok(report.sites().get(2).simcrPrefix()==
            HardwareCfgWriteAudit.PriorSimcr.MATCH_ON_EVERY_MODELED_CFG_PATH,
            "modeled preceding writes are static sites only");
        ok(report.sites().get(3).simcrPrefix()==
            HardwareCfgWriteAudit.PriorSimcr.UNKNOWN_DUE_TO_BARRIER_OR_LIMIT,
            "unknown call invalidates confidence");
        String md=report.markdown();
        ok(md.contains("MM is write-once") &&
            md.contains("its hardware latch remains UNKNOWN") &&
            md.contains("rather than replace or combine as") &&
            md.contains("not the active hardware MM state"),
            "never assert runtime hardware state");
        var generic=HardwareCfgWriteAudit.inspect(false,
            List.of(list.get(0)));
        ok(generic.sites().get(0).mmLiteralBit()==null,
            "generic CPU32 never adopts MC68332 bit interpretation");
        var byteError=HardwareCfgWriteAudit.inspect(true,List.of(
            site(0x2bca,"SIMCR",0xfffa00,false,8,0x40ca,0,0,false,false,false)));
        ok(byteError.sites().get(0).literal()==null &&
            byteError.sites().get(0).mmLiteralBit()==null,
            "partial byte write never treated as known word");
        var unmapped=HardwareCfgWriteAudit.inspect(true,List.of(
            site(0x2bdf,"UNRESOLVED_ALIAS",-1,true,0,null,
                0,0,false,true,true)));
        ok(unmapped.unresolvedAliases()==1 &&
            unmapped.partialOrUnresolvedWrites()==1 &&
            unmapped.sites().get(0).widthBits()==0 &&
            unmapped.markdown().contains(" | UNKNOWN | UNKNOWN |"),
            "unknown-width MOVEM/P-code store is represented, not fatal");
        boolean fail=false;
        try{HardwareCfgWriteAudit.prefix(2,0,false,false,false);}
        catch(IllegalArgumentException expected){fail=true;}
        ok(fail,"invalid counts fail closed");
        fail=false;
        try{HardwareCfgWriteAudit.inspect(true,List.of(
            site(1,"SIMCR",0xfffa00,true,64,0x40ca,0,0,false,false,false)));}
        catch(IllegalArgumentException expected){fail=true;}
        ok(fail,"invalid width fails closed");
        fail=false;try{report.sites().clear();}
        catch(UnsupportedOperationException expected){fail=true;}
        ok(fail,"result immutable");
        System.out.println("HardwareCfgWriteAuditSelfTest OK");
    }
}

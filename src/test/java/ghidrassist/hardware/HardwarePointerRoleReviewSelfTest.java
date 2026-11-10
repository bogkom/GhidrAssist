package ghidrassist.hardware;

import java.util.List;

public final class HardwarePointerRoleReviewSelfTest {
    private static void check(boolean b,String s){if(!b)throw new AssertionError(s);}
    private static HardwarePointerRoleReview.Site hit(long pc,String target,boolean uncertain){
        return new HardwarePointerRoleReview.Site(0x2bc0,"fun_reset",pc,
            "A0","SIM",1,target,uncertain);
    }
    public static void main(String[] args){
        var sites=List.of(hit(0x2bd0,"CSBAR0",false),
            hit(0x2bca,"SIMCR",false),hit(0x2bca,"SIMCR",false));
        var hints=HardwarePointerRoleReview.propose(true,sites,false);
        check(hints.size()==1 && hints.get(0).sites()==2 &&
            hints.get(0).registers()==2,"deduplicate sources and targets");
        check(hints.get(0).status()==HardwarePointerRoleReview.Status.REVIEW_ONLY &&
            hints.get(0).hint().equals("p_hw_sim_mm1_candidate"),"only hint, not symbol");
        check(HardwarePointerRoleReview.csvRows(hints).contains("NEVER_AUTO_APPLY"),
            "CSV cannot silently become Apply item");
        check(HardwarePointerRoleReview.report(hints).contains("No pointer/variable rename"),
            "no invented HighVariable identity");
        check(HardwarePointerRoleReview.propose(false,sites,false).get(0).status()
            ==HardwarePointerRoleReview.Status.FAMILY_UNCERTAIN,"CPU32 no device hints");
        check(HardwarePointerRoleReview.propose(true,sites,true).get(0).status()
            ==HardwarePointerRoleReview.Status.PATH_UNCERTAIN,"truncation must block");
        check(HardwarePointerRoleReview.propose(true,
            List.of(hit(0x2bca,"SIMCR",false),hit(0x2bcc,"CSBAR0",true)),false)
            .get(0).status()==HardwarePointerRoleReview.Status.PATH_UNCERTAIN,
            "unknown-call/STORE barrier blocks");
        check(HardwarePointerRoleReview.propose(true,
            List.of(hit(0x2bca,"SIMCR",false),hit(0x2bcc,"SIMCR",false)),false)
            .get(0).status()==HardwarePointerRoleReview.Status.WEAK_EVIDENCE,
            "repeated same-target access weak");
        check(HardwarePointerRoleReview.propose(true,
            List.of(hit(0x2bca,"SIMCR",false)),false).isEmpty(),"single site omitted");
        boolean immutable=false;
        try{hints.clear();}catch(UnsupportedOperationException ex){immutable=true;}
        check(immutable,"result immutable");
        var crossScope=HardwarePointerRoleReview.propose(true,List.of(
            new HardwarePointerRoleReview.Site(0x2bc0,"fun_reset",0x2bca,
                "A0","SIM",1,"SIMCR",false),
            new HardwarePointerRoleReview.Site(0x2bc0,"fun_reset",0x2bd0,
                "A0","SIM",1,"CSBAR0",false),
            new HardwarePointerRoleReview.Site(0x2bc0,"fun_reset",0x2bd2,
                "A0","QSM",1,"QSMCR",false),
            new HardwarePointerRoleReview.Site(0x2bc0,"fun_reset",0x2bd4,
                "A0","QSM",1,"SPCR0",false)),false);
        check(crossScope.size()==2 &&
            crossScope.stream().allMatch(p->
                p.status()==HardwarePointerRoleReview.Status.SCOPE_CONFLICT &&
                p.hint().isBlank()),
            "same A0 reused for SIM and QSM cannot imply stable register role");
        var crossMm=HardwarePointerRoleReview.propose(true,List.of(
            new HardwarePointerRoleReview.Site(0x2bc0,"fun_reset",0x2bca,
                "A0","SIM",0,"SIMCR",false),
            new HardwarePointerRoleReview.Site(0x2bc0,"fun_reset",0x2bd0,
                "A0","SIM",0,"CSBAR0",false),
            new HardwarePointerRoleReview.Site(0x2bc0,"fun_reset",0x2bd2,
                "A0","SIM",1,"SIMCR",false),
            new HardwarePointerRoleReview.Site(0x2bc0,"fun_reset",0x2bd4,
                "A0","SIM",1,"CSBAR0",false)),false);
        check(crossMm.size()==2 &&
            crossMm.stream().allMatch(p->
                p.status()==HardwarePointerRoleReview.Status.SCOPE_CONFLICT),
            "MM0 and MM1 reuse does not produce confident role hints");
        var differentPointer=HardwarePointerRoleReview.propose(true,List.of(
            new HardwarePointerRoleReview.Site(0x2bc0,"fun_reset",0x2bca,
                "A0","SIM",1,"SIMCR",false),
            new HardwarePointerRoleReview.Site(0x2bc0,"fun_reset",0x2bd0,
                "A0","SIM",1,"CSBAR0",false),
            new HardwarePointerRoleReview.Site(0x2bc0,"fun_reset",0x2bd2,
                "A1","QSM",1,"QSMCR",false),
            new HardwarePointerRoleReview.Site(0x2bc0,"fun_reset",0x2bd4,
                "A1","QSM",1,"SPCR0",false)),false);
        check(differentPointer.size()==2 &&
            differentPointer.stream().allMatch(p->
                p.status()==HardwarePointerRoleReview.Status.REVIEW_ONLY),
            "different registers A0 and A1 have independent role evidence");
        check(HardwarePointerRoleReview.csvRows(crossScope)
            .contains("SCOPE_CONFLICT; NEVER_AUTO_APPLY"),
            "scope conflict remains CSV review only");
        // GA-08/13: pointer-role rows are appended to the *same* legacy
        // seven-column naming preview. Existing function names are
        // untrusted, and giant values must not allocate unbounded CSV.
        var malicious=new HardwarePointerRoleReview.Proposal(
            0x2bc0L,"imported", "\u2060=1+2","SIM",1,2,2,
            HardwarePointerRoleReview.Status.REVIEW_ONLY,"=HYPERLINK(1)");
        String protectedRow=HardwarePointerRoleReview.csvRows(List.of(malicious));
        check(protectedRow.contains("\"'\u2060=1+2 in imported\"") &&
            protectedRow.contains("\"'=HYPERLINK(1)\"") &&
            protectedRow.contains("\"POINTER_ROLE:SIM:MM1\""),
            "directly supplied pointer-role row cannot inject CSV formula");
        String hugeName="=SUM(2,2)"+"X".repeat(1_000_000);
        var huge=new HardwarePointerRoleReview.Proposal(
            0x2bc0L,hugeName,"A0","SIM",1,2,2,
            HardwarePointerRoleReview.Status.REVIEW_ONLY,
            "p_hw_sim_mm1_candidate");
        String limited=HardwarePointerRoleReview.csvRows(List.of(huge));
        check(limited.contains("SOURCE_TRUNCATED") &&
            limited.length()<1400 && limited.contains("NEVER_AUTO_APPLY"),
            "million-character Ghidra function name is bounded and marked");
        var overflow=java.util.Collections.nCopies(
            HardwarePointerRoleReview.MAX_CSV_ROWS+4,hints.get(0));
        String omitted=HardwarePointerRoleReview.csvRows(overflow);
        check(omitted.lines().count()==
            HardwarePointerRoleReview.MAX_CSV_ROWS+1 &&
            omitted.contains("4 rows omitted") &&
            omitted.contains("INCOMPLETE_EXPORT_NEVER_AUTO_APPLY") &&
            omitted.contains("POINTER_ROLE_EXPORT_INCOMPLETE"),
            "bounded rows must disclose four missing hint proposals");
        boolean nullRejected=false;
        var malformed=new java.util.ArrayList<
            HardwarePointerRoleReview.Proposal>();
        malformed.add(hints.get(0));malformed.add(null);
        try{HardwarePointerRoleReview.csvRows(malformed);}
        catch(IllegalArgumentException expected){nullRejected=true;}
        check(nullRejected,"missing pointer role must not disappear silently");
        nullRejected=false;
        try{HardwarePointerRoleReview.csvRows(null);}
        catch(IllegalArgumentException expected){nullRejected=true;}
        check(nullRejected,"null pointer role export rejected");
        check(HardwarePointerRoleReview.csvRows(hints)
            .contains("A0 in fun_reset") &&
            HardwarePointerRoleReview.csvRows(hints)
            .contains("p_hw_sim_mm1_candidate"),
            "ordinary pointer-role rows stay unchanged");
        // One static instruction can be listed repeatedly as the SAME
        // witness, but a different register, target or function name at
        // that PC must not generate a confident register-role proposal.
        var contradictoryPc=new java.util.ArrayList<>(sites);
        contradictoryPc.add(hit(0x2bca,"CSOR0",false));
        var ambiguous=HardwarePointerRoleReview.propose(
            true,contradictoryPc,false);
        check(ambiguous.size()==1 &&
            ambiguous.get(0).status()==HardwarePointerRoleReview.Status.PATH_UNCERTAIN &&
            ambiguous.get(0).hint().isBlank(),
            "same PC with different MMIO targets cannot produce stable A-register hint");
        var reversedWitness=new java.util.ArrayList<>(contradictoryPc);
        java.util.Collections.reverse(reversedWitness);
        check(HardwarePointerRoleReview.propose(true,reversedWitness,false)
                .get(0).status()==HardwarePointerRoleReview.Status.PATH_UNCERTAIN,
            "PC source conflict classification must not depend on input order");
        var switchedName=new java.util.ArrayList<>(sites);
        switchedName.add(new HardwarePointerRoleReview.Site(
            0x2bc0,"name_after_edit",0x2bd0,"A0","SIM",1,"CSBAR0",false));
        check(HardwarePointerRoleReview.propose(true,switchedName,false)
                .get(0).status()==HardwarePointerRoleReview.Status.PATH_UNCERTAIN,
            "mixed function names from two revisions cannot promote pointer hint");
        var differentPtrAtPc=new java.util.ArrayList<>(sites);
        differentPtrAtPc.add(new HardwarePointerRoleReview.Site(
            0x2bc0,"fun_reset",0x2bd0,"A1","SIM",1,"CSBAR0",false));
        check(HardwarePointerRoleReview.propose(true,differentPtrAtPc,false)
                .get(0).status()==HardwarePointerRoleReview.Status.PATH_UNCERTAIN,
            "same PC cannot prove two distinct pointer register roles");
        var validDuplicated=HardwarePointerRoleReview.propose(true,
            List.of(hit(0x2bd0,"CSBAR0",false),
                    hit(0x2bd0,"CSBAR0",false),
                    hit(0x2bca,"SIMCR",false)),false);
        check(validDuplicated.size()==1 &&
            validDuplicated.get(0).status()==HardwarePointerRoleReview.Status.REVIEW_ONLY,
            "identical duplicated source PC is deduplicated, not an invented ambiguity");
        boolean refusedOversized=false;
        try {
            HardwarePointerRoleReview.propose(true,
                java.util.Collections.nCopies(
                    HardwarePointerRoleReview.MAX_SOURCE_SITES+1,
                    hit(0x2bca,"SIMCR",false)),false);
        }catch(IllegalArgumentException expected){refusedOversized=true;}
        check(refusedOversized,
            "oversized pointer-role source catalog rejected before grouping");
        System.out.println("HardwarePointerRoleReviewSelfTest OK");
    }
}

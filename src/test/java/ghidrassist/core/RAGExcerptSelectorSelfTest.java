package ghidrassist.core;
public final class RAGExcerptSelectorSelfTest {
    private static void ok(boolean b,String m){if(!b)throw new AssertionError(m);}
    public static void main(String[] args) {
        String meta="[RAG_SOURCE_METADATA document_id=MC68332UM models=MC68332 part=FULL_MANUAL pdf_page=215]\n";
        String table="APPENDIX D REGISTER SUMMARY\nTable D-1 Module Address Map\n"+
            "Module Size Base Address\nSIM 128 $YFFA00\nTPURAM CNTL 64 $YFFB00\n"+
            "QSM 512 $YFFC00\nTPU 512 $YFFE00\n"+
            "MM=0: $7FF000-$7FFFFF; MM=1: $FFF000-$FFFFFF\n";
        String page=meta+"[POSSIBLE TABLE / COLUMNS: VERIFY PDF]\n"+table+
            "[GEOMETRY-ALIGNED MODULE ADDRESS TABLE CANDIDATES]\n"+
            "pdf_page=215 module=SIM size_bytes=128 base_as_printed=$YFFA00\n";
        String result=RAGExcerptSelector.select(page,"MC68332UM SIMCR MM TPURAM CNTL YFFB00");
        ok(result.contains("SIM 128 $YFFA00") && result.contains("TPURAM CNTL 64 $YFFB00"),"source rows not truncated");
        ok(result.contains("QSM 512") && result.contains("TPU 512"),"four module rows preserved");
        ok(!result.contains("RAG_SOURCE_METADATA"),"header removed from excerpt");
        ok(RAGExcerptSelector.evidenceScore(page,"Table D-1 Module Address Map") >
           RAGExcerptSelector.evidenceScore(meta+"Table D-1 Module Address Map...215",
               "Table D-1 Module Address Map"),"body table ranks over TOC reference");
        StringBuilder longPage=new StringBuilder(meta);
        for(int i=0;i<200;i++)longPage.append("unrelated data ").append(i).append('\n');
        longPage.append(table);
        String tail=RAGExcerptSelector.select(longPage.toString(),"YFFB00 YFFC00",1000);
        ok(tail.contains("$YFFB00") && tail.contains("$YFFC00"),"focus on addresses in long page");
        ok(tail.length()<1200,"bounded snippet");
        System.out.println("RAGExcerptSelectorSelfTest OK");
    }
}

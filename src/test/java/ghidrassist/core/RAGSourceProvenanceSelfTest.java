package ghidrassist.core;

import ghidrassist.hardware.HardwareBitfieldSourceLedger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/** GA-06/10/16: exact indexed hash versus changed on-disk PDF. */
public final class RAGSourceProvenanceSelfTest {
    private RAGSourceProvenanceSelfTest() {}
    private static int checks;
    private static void ok(boolean b,String why) {
        checks++;if(!b)throw new AssertionError(why);
    }
    private static void blocked(IoAction f,String why)throws Exception {
        boolean refused=false;
        try{f.run();}catch(java.io.IOException expected){refused=true;}
        ok(refused,why);
    }
    @FunctionalInterface interface IoAction {void run()throws Exception;}
    private static String sha(byte[] b)throws Exception {
        return HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(b));
    }
    public static void main(String[] args)throws Exception {
        var pin=HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256;
        var known=RAGSourceProvenance.inspect("PDF",pin);
        ok(known.pin()==RAGSourceProvenance.Pin.OFFICIAL_MC68332UM_SHA256_AT_INDEX &&
            known.evidence().contains("INDEX_TIME_ONLY_CURRENT_FILE_UNVERIFIED") &&
            known.evidence().contains("EXPLICIT_REQUIRED") &&
            known.evidence().contains("NOT_INDEPENDENTLY_VALIDATED"),
            "Known pinned PDF bytes remain index-only with no implicit MCU profile");
        ok(RAGSourceProvenance.inspect("pdf","0".repeat(64)).pin()==
            RAGSourceProvenance.Pin.OTHER_INDEXED_PDF,
            "Valid unknown digest is not the official MC68332UM");
        ok(RAGSourceProvenance.inspect("pdf",null).pin()==
            RAGSourceProvenance.Pin.INDEX_DIGEST_UNKNOWN &&
            RAGSourceProvenance.inspect("pdf","zz").indexedSha256().equals("UNKNOWN"),
            "Legacy or malformed digest stays UNKNOWN");
        ok(RAGSourceProvenance.inspect("text",pin).pin()==
            RAGSourceProvenance.Pin.NOT_PDF,
            "PDF pin cannot grant document scope to source code");
        Path directory=Files.createTempDirectory("ga-rag-source-");
        Path pdf=directory.resolve("manual.pdf");
        Path link=directory.resolve("manual-link.pdf");
        try {
            byte[] body="%PDF-1.4\nSynthetic private-free PDF checksum fixture\n"
                .getBytes(StandardCharsets.US_ASCII);
            String digest=sha(body);
            Files.write(pdf,body);
            RAGSourceProvenance.requireCurrentPdf(pdf,digest);
            checks++;
            blocked(()->RAGSourceProvenance.requireCurrentPdf(pdf,"0".repeat(64)),
                "A modified/forged indexed digest cannot authorize opening");
            blocked(()->RAGSourceProvenance.requireCurrentPdf(pdf,null),
                "Missing historic index digest must fail closed");
            blocked(()->RAGSourceProvenance.requireCurrentPdf(pdf,
                digest.toUpperCase(java.util.Locale.ROOT)),
                "Noncanonical legacy digest cannot silently match");
            blocked(()->RAGSourceProvenance.requireCurrentPdf(pdf,digest,8),
                "Size bound refuses PDF before exhausting the stream");
            Files.writeString(pdf,"%PDF-1.4\nCHANGED BY USER",StandardCharsets.US_ASCII);
            blocked(()->RAGSourceProvenance.requireCurrentPdf(pdf,digest),
                "Underlying PDF edit after indexing rejected");
            Files.writeString(pdf,"NOT_A_PDF",StandardCharsets.US_ASCII);
            blocked(()->RAGSourceProvenance.requireCurrentPdf(pdf,
                sha(Files.readAllBytes(pdf))),
                "Digest match without PDF header is insufficient");
            blocked(()->RAGSourceProvenance.requireCurrentPdf(
                directory.resolve("missing.pdf"),digest),
                "Missing PDF cannot inherit former source evidence");
            Files.write(pdf,body);
            try{
                Files.createSymbolicLink(link,pdf.getFileName());
                blocked(()->RAGSourceProvenance.requireCurrentPdf(link,digest),
                    "Symlink source not trusted as immutable local PDF");
            }catch(UnsupportedOperationException|java.nio.file.FileSystemException unsupported){
                // Target runners support symlinks; unsupported filesystems
                // still exercise regular-file and digest checks.
            }
            var hit=new SearchResult("MC68332UM.pdf","SIMCR",0.9,0,
                pdf.toString(),"pdf",219,false,digest);
            ok(digest.equals(hit.getIndexedSha256()) &&
                hit.getPageNumber()==219 &&
                RAGSourceProvenance.inspect(hit.getSourceType(),
                    hit.getIndexedSha256()).pin()==
                    RAGSourceProvenance.Pin.OTHER_INDEXED_PDF,
                "Search result retains exact hash without pretending its source is official");
            var legacy=new SearchResult("legacy.pdf","MM",0.9,2,
                pdf.toString(),"pdf",1,true);
            ok(legacy.getIndexedSha256()==null,
                "Previous SearchResult constructor preserves unpinned legacy state");
            ok(Files.size(pdf)==body.length,
                "Read-only validation never modifies the source PDF");
        }finally{
            Files.deleteIfExists(link);
            Files.deleteIfExists(pdf);
            Files.deleteIfExists(directory);
        }
        System.out.println("RAGSourceProvenanceSelfTest PASS: checks="+checks);
    }
}

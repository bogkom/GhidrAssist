package ghidrassist.core;

import ghidrassist.hardware.HardwareBitfieldSourceLedger;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;

/**
 * GA-06/10/16: explicitly separate indexed PDF checksum metadata,
 * reviewed public MC68332UM bytes and the CURRENT local file.
 * No implicit device selection, PDF parsing, firmware/Ghidra write,
 * edition/page authentication or Review/Apply authority.
 */
public final class RAGSourceProvenance {
    private RAGSourceProvenance() {}
    public static final long MAX_OPEN_PDF_BYTES=128L*1024*1024;
    public enum Pin {
        OFFICIAL_MC68332UM_SHA256_AT_INDEX,
        OTHER_INDEXED_PDF, INDEX_DIGEST_UNKNOWN, NOT_PDF
    }
    public record Assessment(String indexedSha256,Pin pin) {
        public String evidence() {
            return " INDEXED_SHA256: "+indexedSha256+
                " PDF_PIN: "+pin+
                " PROVENANCE: INDEX_TIME_ONLY_CURRENT_FILE_UNVERIFIED"+
                " MCU_SELECTION: EXPLICIT_REQUIRED"+
                " PDF_EDITION_PAGE_CONTENT: NOT_INDEPENDENTLY_VALIDATED";
        }
    }
    private static boolean validSha(String hash) {
        return hash!=null && hash.matches("[0-9a-f]{64}");
    }
    public static Assessment inspect(String sourceType,String indexedSha256) {
        if(!"pdf".equalsIgnoreCase(sourceType))
            return new Assessment("UNKNOWN",Pin.NOT_PDF);
        if(!validSha(indexedSha256))
            return new Assessment("UNKNOWN",Pin.INDEX_DIGEST_UNKNOWN);
        return new Assessment(indexedSha256,
            indexedSha256.equals(
                HardwareBitfieldSourceLedger.MC68332_PUBLIC_PDF_SHA256)?
                    Pin.OFFICIAL_MC68332UM_SHA256_AT_INDEX:
                    Pin.OTHER_INDEXED_PDF);
    }

    /**
     * Confirm the exact same bytes were present before and after indexing
     * or an unchanged-file shortcut. Both digests must be real canonical
     * SHA-256 values. A changing source refuses import BEFORE Lucene's
     * atomic update. This is still not an OS-level file lock.
     */
    public static void requireStableIndexBytes(String beforeHash,long beforeSize,
            String afterHash,long afterSize)throws IOException {
        if(!validSha(beforeHash) || !validSha(afterHash) ||
                beforeSize<0 || afterSize<0 ||
                beforeSize!=afterSize || !beforeHash.equals(afterHash))
            throw new IOException(
                "Document changed while indexing; reimport unchanged source");
    }

    /**
     * Guard opening a file at an indexed PDF page. A filename, PDF header,
     * old Lucene digest, or publisher URL by itself cannot establish that
     * the file currently at that path has unchanged bytes. Reject absent/
     * malformed digests, symlinks, changed/missing/oversized/non-PDF files.
     * This is a read-only pre-open check, not an OS-level atomic guarantee
     * about a subsequent external PDF viewer launch.
     */
    public static void requireCurrentPdf(Path file,String indexedSha256)
            throws IOException {
        requireCurrentPdf(file,indexedSha256,MAX_OPEN_PDF_BYTES);
    }
    static void requireCurrentPdf(Path file,String indexedSha256,long maxBytes)
            throws IOException {
        if(file==null || !validSha(indexedSha256) ||
                maxBytes<5 || maxBytes>MAX_OPEN_PDF_BYTES)
            throw new IOException("Missing/invalid indexed PDF digest; reindex document");
        BasicFileAttributes before=Files.readAttributes(file,
            BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
        if(!before.isRegularFile() || before.isSymbolicLink() ||
                before.size()<5 || before.size()>maxBytes)
            throw new IOException("Indexed PDF path is not a bounded regular file");
        byte[] signature=new byte[5];
        long count=0;
        MessageDigest digest;
        try {digest=MessageDigest.getInstance("SHA-256");}
        catch(NoSuchAlgorithmException impossible){throw new IOException(impossible);}
        try(InputStream in=Files.newInputStream(file)) {
            byte[] buf=new byte[8192];
            for(int n;(n=in.read(buf))!=-1;) {
                if(n==0) {
                    int one=in.read();
                    if(one<0)break;
                    buf[0]=(byte)one;n=1;
                }
                if(count+n>maxBytes)
                    throw new IOException("Indexed PDF exceeds verification size limit");
                for(int i=0;i<n && count+i<5;i++)
                    signature[(int)(count+i)]=buf[i];
                digest.update(buf,0,n);
                count+=n;
            }
        }
        BasicFileAttributes after=Files.readAttributes(file,
            BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
        if(count!=before.size() || count!=after.size() ||
                !before.lastModifiedTime().equals(after.lastModifiedTime()) ||
                !java.util.Objects.equals(before.fileKey(),after.fileKey()) ||
                !after.isRegularFile() || after.isSymbolicLink())
            throw new IOException("Indexed PDF changed during source verification");
        if(signature[0]!='%' || signature[1]!='P' || signature[2]!='D' ||
                signature[3]!='F' || signature[4]!='-')
            throw new IOException("Indexed source is not a PDF header");
        if(!HexFormat.of().formatHex(digest.digest()).equals(indexedSha256))
            throw new IOException("Source PDF changed since indexing; reimport before opening");
    }
}

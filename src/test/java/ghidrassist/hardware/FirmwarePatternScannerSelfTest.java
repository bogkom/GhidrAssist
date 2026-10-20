package ghidrassist.hardware;

import java.util.List;

/** Fixed synthetic byte fixtures: never copy private ECU image into public CI. */
public final class FirmwarePatternScannerSelfTest {
    private static void require(boolean v,String what){
        if(!v)throw new AssertionError(what);
    }
    private static void place(byte[] image,int at,int... bytes){
        for(int n:bytes)image[at++]=(byte)n;
    }
    public static void main(String[] args){
        byte[] fake=new byte[512];
        place(fake,0x10,0x33,0xfc,0x40,0xca,0x00,0xff,0xfa,0x00);
        place(fake,0x28,0x33,0xfc,0xff,0xf0,0x00,0xff,0xfb,0x04);
        place(fake,0x40,0x33,0xfc,0xff,0x88,0x00,0xff,0xfa,0x68);
        place(fake,0x60,0x42,0x79,0x00,0xff,0xfa,0x74);
        place(fake,0x70,0x23,0xfc,0x01,0x00,0x00,0x00,0x00,0xff,0xfb,0x00);
        place(fake,0x90,0x4e,0x7b,0x88,0x01);
        place(fake,0xa0,0x4e,0x7b,0x98,0x01);
        place(fake,0xb0,0x33,0xfc,0x40,0xca,0x00,0x12,0x34,0x56); // elsewhere
        FirmwarePatternScanner.Report report=FirmwarePatternScanner.scan(fake,0xfff000,0xffffff);
        require(report.hits.size()==5,"five module-range immediate writes/clears");
        require(report.count(FirmwarePatternScanner.Kind.MOVE_WORD)==3,"word count");
        require(report.count(FirmwarePatternScanner.Kind.MOVE_LONG)==1,"long count");
        require(report.count(FirmwarePatternScanner.Kind.CLR_WORD)==1,"clear count");
        require(report.hits.get(0).offset==0x10 &&
            report.hits.get(0).value==0x40ca &&
            report.hits.get(0).absoluteAddress==0xfffa00,"SIMCR word pattern");
        require(report.hits.get(4).value==0x1000000L &&
            report.hits.get(4).absoluteAddress==0xfffb00,"TRAMMCR width-sensitive pattern");
        require(FirmwarePatternScanner.findMovecToVbr(fake).equals(List.of(0x90,0xa0)),
            "VBR control register extension word");
        require(FirmwarePatternScanner.scan(fake,0xfffa68,0xfffa68).hits.size()==1,
            "address filter");
        boolean unsafe=false;
        try{FirmwarePatternScanner.scan(fake,0xffffff,0xfff000);}
        catch(IllegalArgumentException e){unsafe=true;}
        require(unsafe,"bad address range must fail");
        System.out.println("FirmwarePatternScannerSelfTest OK");
    }
}

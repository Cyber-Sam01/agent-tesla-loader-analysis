import "pe"
import "math"

rule MAL_DotNet_PearlFarm_ImageLoader
{
    meta:
        description = "Detects the PearlFarm decoy .NET loader that rebuilds a hidden payload from a bitmap resource"
        author      = "Samuel Adetola O."
        date        = "2026-10-15"
        sample      = "412bad1c87f5d4e8c3a6955e942628b9615931cc2399c2b316326d15e3a84775"
        confidence  = "high for this build, medium for related builds"
        status      = "draft - tested on the analysed sample only"

    strings:
        $cls1  = "CompressionInspiredExtractor" ascii
        $cls2  = "ComputeCompressionMetrics" ascii
        $cls3  = "PixelByteSequence" ascii
        $cls4  = "PixelByteEnumerator" ascii
        $guid  = "a81f3d5e-792b-4c92-b58a-12e4c89a07d3" ascii wide
        $array = "ABABABCDABABCDEFABABCDABGHIJABAB" ascii
        $delim = "~***111***111~" wide

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            3 of ($cls*) or
            ($delim and 1 of ($cls*)) or
            ($guid and $array)
        )
}

rule HUNT_DotNet_Exe_Dominant_HighEntropy_Text
{
    meta:
        description = "Hunting only: .NET EXE where .text is nearly the whole file and looks encrypted or compressed"
        author      = "Samuel Adetola O."
        date        = "2026-10-15"
        confidence  = "low - expect false positives from packed or bundled apps"

    condition:
        uint16(0) == 0x5A4D and
        filesize > 500KB and filesize < 5MB and
        pe.imports("mscoree.dll", "_CorExeMain") and
        for any s in pe.sections : (
            s.name == ".text" and
            s.raw_data_size * 10 > filesize * 9 and
            math.entropy(s.raw_data_offset, s.raw_data_size) > 7.4
        )
}

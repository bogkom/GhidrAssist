# MCP + RAG hardware analysis regression (October 2026)

The firmware is analyzed as Ghidra language 68000:BE:32:CPU32.
This is not proof that the actual processor is MC68332.

## Reproduction and literal data

The disassembly of the test function contains these immediate writes:

| Instruction | Destination | Word |
| --- | --- | --- |
| 0006ea28 | 00fffa4c | F803 |
| 0006ea30 | 00fffa4e | 3870 |
| 0006ea38 | 00fffa50 | F803 |
| 0006ea40 | 00fffa52 | 5870 |

Before the fix, the RAG context contained mostly generic pin-assignment and QSPI
material; the LLM falsely claimed that the function performed no direct writes
to CS0/CS1 configuration registers.

The addresses and words above come from MCP disassembly. Register names
CSBAR0/CSOR0/CSBAR1/CSOR1 are conditional on a *verified* MC68332 register map.

## Changes

- RAG query focus retains CSBAR/CSOR even alongside SIMCR.
- Retrieval uses separate, deduplicated queries for option, base-address and
  bit-field documentation in addition to the general user query.
- Page excerpt selection favors option tables with DSACK evidence.
- MCP disassembly results now carry an independent, bounded ledger of literal
  writes, two's-complement values, binary XOR and bit positions, with provenance.
- ReAct cannot add more tasks when at least half the planned tasks are complete;
  prompts discourage redundant read calls and contradictions.

## Offline self-tests (no Ghidra installation needed)

    javac -d /tmp/ga-selftests \
      src/main/java/ghidrassist/core/RAGQueryFocus.java \
      src/main/java/ghidrassist/core/RAGExcerptSelector.java \
      src/main/java/ghidrassist/hardware/McpEvidenceGuard.java \
      src/test/java/ghidrassist/core/RAGQueryFocusSelfTest.java \
      src/test/java/ghidrassist/core/RAGExcerptSelectorSelfTest.java \
      src/test/java/ghidrassist/hardware/McpEvidenceGuardSelfTest.java
    java -cp /tmp/ga-selftests ghidrassist.core.RAGQueryFocusSelfTest
    java -cp /tmp/ga-selftests ghidrassist.core.RAGExcerptSelectorSelfTest
    java -cp /tmp/ga-selftests ghidrassist.hardware.McpEvidenceGuardSelfTest

Full extension builds require GHIDRA_INSTALL_DIR pointing to Ghidra 12.1.4.

## Limits

A text Lucene index does not prove the geometry of a multi-column PDF table or
fully recover drawings. Validate uncertain bit layouts against the source PDF page.
The new MCP evidence guard detects *literal* writes and computes bit math; it does
not verify the physical MCU or prove a runtime execution path, nor is it a
general-purpose proof checker for every LLM assertion.

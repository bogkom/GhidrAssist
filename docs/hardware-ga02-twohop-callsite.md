# GA-02/03 — ograniczony, dwupoziomowy przepływ rejestrów przez CALL

## Zależności i status

Ten pakiet jest zależny od przetestowanego **PR #135**:
[GA-02/03 × GA-11](https://github.com/bogkom/GhidrAssist/pull/135),
`da2c4a6e42b46e34e812442083d4f1cd1345e0df`, **43/43 GitHub
Actions SUCCESS**. Zachowuje źródłowy odczyt relokowanych VBR/ISR z GA-11,
jednopoziomowe CALL z GA-02/03 i dotychczasowy trwały cache GA-12.
Obszary nadal pozostają **CZĘŚCIOWO**.

Nie modyfikować historycznych PR #133–#135 ani nie scalać dużego stosu
do `master` bez osobnej decyzji użytkownika.

## Co analizator potwierdza źródłowo

Wymagany **jawny profil MC68332**. Analiza dotyczy konkretnych
instrukcji i ich możliwych zależności w Listing/CFG, nie przebiegu ECU:

```asm
outer:
  MOVEA.L #0xFFFA00,A0
  MOVE.L  #0x40CA,D0
  JSR     bridge
  RTS

bridge:
  MOVEA.L A0,A1
  JSR     leaf
  RTS

leaf:
  MOVE.W  D0,(A1)
  RTS
```

Dla **jednego dokładnego PC wywołania** `outer → bridge`, bazując
wyłącznie na wartościach A/D zgodnych na wszystkich możliwych
poprzednikach CFG w funkcji `outer`:

1. Dekoduj **jedną** funkcję pośrednią: pełne, ciągłe ciało do 64
   instrukcji, wyłącznie znane transfery rejestrów, `NOP`, `RTS`
   lub statycznie znane gałęzie. Wymagany DAG (bez cykli i
   niedostępnych bloków), **dokładnie jedno** bezpośrednie CALL
   na początku rozpoznanej funkcji końcowej.
2. Odrzuć pośrednika przy innych CALL, `STORE`, `MOVEC`, `CALLOTHER`,
   skoku obliczanym/poza funkcję, niekompletnym Listing albo
   rozbieżnej rewizji Ghidra Program. Nie domniemaj nieznanych
   skutków ubocznych.
3. Przeanalizuj samą funkcję pośrednią **w nowym, nieutrwalanym
   kontekście** z wartościami przekazanymi z konkretnego outer CALL.
   Pobierz tylko rejestry uzgodnione w jej własnym CFG bezpośrednio
   **przed jedynym wewnętrznym CALL**.
4. Zastosuj dotychczasowy, konserwatywny analizator `one-hop`
   do funkcji końcowej, lecz wyłącznie z wartościami z tego
   konkretnego wewnętrznego CALL. Funkcja końcowa nie może
   zawierać kolejnych CALL ani nieznanych skoków.
5. W oddzielnym raporcie źródłowym `SOURCE-ONLY MAY-CANDIDATES`
   pokaż łańcuch `outer function/PC → bridge function/PC → leaf/STORE PC`,
   kandydacki adres i wartość MMIO, szerokość oraz oznaczenia
   wcześniejszych nieznanych efektów. **Nie zapisuj** tych wyników do
   bazowego `rawCfgMmioSites`, checkpointów GA-12 ani Review/Apply/Undo.

### Ważna poprawka A7

Instrukcja `JSR/BSR` zapisuje adres powrotu na stosie CPU32.
**A7 z punktu tuż przed CALL nie jest więc dowodem tej samej wartości
A7 po wejściu do callee.** Zarówno jednopoziomowy, jak i dwupoziomowy
analizator odrzuca A7 na każdej granicy CALL. Nie wyprowadza adresu
MMIO z takiego argumentu ani nie przelicza go arbitralnie o 4 bajty.

Pozostałe rejestry A/D są tylko potencjalnymi wartościami źródłowymi;
algorytm nie zakłada konwencji ABI, rzeczywistego wykonania danej
ścieżki ani wartości sprzętu po zmianach SIMCR/MM.

### Limity

- maks. 32 **outer CALL** na jeden przebieg (z puli najwyżej 96
  jednopoziomowych kontekstów źródłowych);
- maks. 64 instrukcje funkcji pośredniej i 1 bezpośredni nested CALL;
- maks. 128 instrukcji funkcji końcowej, 48 wierszy formatu
  (w produkcyjnej konfiguracji 40);
- brak rekurencji, iteracyjnego interproceduralnego fixed point
  ani propagacji pomiędzy trzema i więcej CALL;
- nieznane cele, cykle, niepełne CFG, rozbieżne wartości, nieznany
  adres STORE, limity i niezamapowane MMIO to jawne
  **UNKNOWN/INCOMPLETE**, a nie dowód braku efektów.

Nie twierdzić o wykonanym RESET/CALL, zatrzaśniętym MM, fizycznej
magistrali CS, aktywnym VBR ani ISR. Dane z oryginalnego firmware
ECU411 i produkcyjne projekty Ghidry są poza zakresem.

## Regresje

- **Java 21** `HardwareTwoHopRegisterFlowSelfTest`: dwie różne pary
  wartości A0/D0 przez tę samą funkcję pośrednią, `MOVEA` do A1,
  niezależne MMIO, brak globalnego źródła callee, rozbieżne
  gałęzie, A7 na obu granicach CALL, odrzucenie niedekodowanego
  pośrednika, nested CALL, zapisów pośrednika, cykli, nieznanych
  targetów, ograniczeń i brak deterministycznego mieszania
  między callerami.
- **Rzeczywista syntetyczna Ghidra 12.1.4 PUBLIC**:
  `Ga11VectorHeadlessMain` w nowym trybie `two-hop`,
  dwaj różni wywołujący, rzeczywisty `MOVEA.L A0,A1; JSR leaf`,
  końcowe `MOVE.W D0,(A1)`, nieznany alias z trzeciego
  wywołania, oddzielny raport, brak Apply, ponowna deterministyczna
  analiza i negatywny generic CPU32. Kontrola `modificationNumber`
  potwierdza brak edycji podczas analizy.
- **GitHub Actions**: pełne Java25 `buildExtension` dla
  Ghidry 12.1.4 PUBLIC, Java21 źródłowe i rzeczywista syntetyczna
  Ghidra headless; stare regresje jednopoziomowe, GA-11 VBR,
  GA-12 checkpointy, Xvfb/Automation API tam, gdzie wyzwolone.

Wyse, Precision, timery i Codex Supervisor pozostają zatrzymane.

## Aktualizacja bezpieczeństwa wejść — 2026-11-04

Bounded two-hop stosuje ten sam parser/walidator zbioru MMIO co
one-hop: najwyżej **4096 adresów wejściowych** w fizycznym
24-bitowym zakresie MC68332, bez `null`. Brak adresu nie może być
cicho pominięty ani potraktowany jako kompletny dowód braku aliasu;
przekroczenie limitu odmawia całej analizy kontekstowej. Zbiór
jest dalej używany wyłącznie jako źródłowy kontekst zasięgu, nie jako
mapowanie magistrali ani jako uprawnienie Apply.

Nowe Java21 regresje sprawdzają 24-bitową granicę, `null`,
4096/4097 elementów i to, że poprawny dwupoziomowy przepływ
`outer → bridge → leaf STORE` oraz wcześniejsze wyniki pozostają
niezmienne. Ghidra 12.1.4 PUBLIC / Java25 i rzeczywiste
syntetyczne Ghidra headless wymagają odrębnego CI PASS na
końcowym SHA; testy lokalne Wyse/Precision pozostają zatrzymane.

## 2026-11-05 — Unknown-width STORE alias safety through CALL

A direct, context-seeded CALL can prove the start address of an indirect
memory write without proving its access width. For instance, an unknown
write at `0xFFF9FE` can span the `0xFFFA01` SIMCR MM low byte if it is
at least four bytes wide. Filtering such a write as non-MMIO simply because
its **start** is absent from the tracked MC68332 register set is unsound.

Unknown/unmodeled STORE widths (anything other than 8, 16 or 32 bits) now
increment the read-only `unresolvedAliases` counter, even when the
instruction's effective address is known. They do not become precise
`Candidate` rows or a known written word. A proved 32-bit write crossing
`0xFFFA01` remains a possible MMIO source, while an 8-bit write at the
same start is excluded. The two-hop analyzer inherits this fail-closed
behavior through its existing direct-leaf CALL solver, with a separate
Java21 regression for both widths.

This is source-only uncertainty, not execution, an active SIMCR MM latch,
a physical bus map, verified Ghidra Apply permission or a firmware edit.

## 2026-11-05 — real CPU32 indexed STORE through two direct JSRs

The existing real synthetic 12.1.4 headless `two-hop` fixture
establishes two independent A0/D0 caller contexts through one
ordinary bridge into a direct leaf `MOVE.W D0,(A1)`.
It does not establish that `D1.W` is propagated as an index in the
**Ghidra-decoded** leaf operand.

A second isolated `two-hop-indexed` mode adds actual CPU32 bytecode
for `MOVE.W D0,1(A1,D1.W)`. A direct outer caller seeds A0=SIMCR
(or CSBAR) and D0 with a constant and D1.W=-1 using `MOVEQ`; the
bridge copies A0 to A1 before its one direct JSR. The leaf's decoded
operand must be accepted by the strict indexed-address parser and
compute A1 + sign_extend(D1.W) + 1 under modulo-24-bit addressing.
Two callers must produce separate context-specific 16-bit candidate
rows. A third caller lacking D1 must yield an **unresolved alias**
and no precise candidate. The same run also checks the nested
JSR targets, exact CPU32 instruction encoding, output determinism
after process-local GA-12 reuse, source-only/non-Apply classification,
MC68332 profile gate, and unchanged Program revision.

The deterministic pure-Java regression adds a bridge with a signed
index, a missing index, disagreeing branch predecessors, and an
unrelated non-MMIO address. The new Actions workflow performs a full
Ghidra 12.1.4 PUBLIC/Java25 extension build from a checksum-verified
release, then runs the test **inside real synthetic headless Ghidra**,
saving the exact extension and harness SHA-256 in the artifact.
No original ECU411 firmware or user project is used.

These are **possible static MMIO source candidates**, never executed
CALL traces, an active SIMCR MM bit or proof of the physical bus map.

### Actual Ghidra indexed operand decoder finding

The new real CPU32 fixture exposed the genuine operand syntax
`(0x1,A1,D1w*0x1)`. The previous strict parser required
`D1.W*1`; it therefore failed to extract a verified index even
though Ghidra decoded the CPU32 instruction and the two JSRs.
The parser was amended to accept both equivalent spellings with
only scales 1/2/4/8 and word/long index widths. A dedicated
Java21 parser regression accompanies the real integration test;
this is a source parser compatibility fix, not a new general
interprocedural solver or a claim of MMIO execution.

### Confirmed MOVEQ caller-input issue in the indexed acceptance test

The actual `MOVEQ #-1,D1` instruction printed as `moveq -0x1,D1`
in Ghidra 12.1.4. Previously, the immediate detector required a
literal `#`, classified D1 as clobbered, and lost the signed index
before the **outer** JSR. The new source gate accepts this numeric
form only for `MOVEQ`, with Ghidra's own `Scalar` required.
Strict Java21 negative tests ensure that ordinary memory/register
operands are not upgraded to full register constants.
The final real fixture asserts both the decoded signed MOVEQ
operand and two independent indexed MMIO candidate rows.

## 2026-11-05 — indexed scale/sign and MCU24 wrap through two real CALLs

An independent genuine synthetic Ghidra acceptance mode
`two-hop-indexed-wrap` extends the existing proof beyond
index scale 1 and non-wrapping offsets. The decoded leaf is
`MOVE.W D0,(A1,D1.W*2)` and two independent caller
contexts use `A0=0`, a fully known positive `D1.L`
with negative low word, and distinct D0 values. Sign
extension of `D1.W`, multiplication by 2, and modulo-24
bus arithmetic yield possible SIMCR and CSBAR sources.
A missing D1 stays an explicit unknown alias; the
equivalent `D1.L` source does not accidentally inherit
the .W negative interpretation.

This is strictly read-only Ghidra 12.1.4 PUBLIC/Java25
synthetic headless evidence on exact CI SHA, not an
executed two-CALL trace or physical memory-map proof.

## 2026-11-10 — closed CPU32 bridge control-flow semantics

The bounded two-hop source solver now rejects **structurally connected but
semantically impossible** intermediate CALL CFGs before propagating the
outer caller's A/D values into a nested leaf STORE:

- Conditional CPU32 `Bcc` requires **two distinct** successors (jump and
  fallthrough); an unconditional `BRA` requires exactly **one**; `NOP`,
  immediate register definitions, copies, adjustments and conservative
  clobbers are linear one-successor instructions. Only a decoded ordinary
  `RTS` can terminate the bridge without a successor.
- The one intermediate `CALL_BARRIER` must be a `JSR` or `BSR` and
  retain exactly one local return successor. A non-branch operation cannot
  impersonate a branch/return by changing its `Kind`. Unexpected implicit
  A/D effects on `Bcc/BRA/NOP` are not silently accepted as inert.
- Intermediate function entry, branch instruction PCs and target CALL
  coordinate must be aligned MCU24 source identities; mismatched/out-of-
  range and self-recursive bridges become **rejected/UNKNOWN**, not a
  potentially valid argument flow or a report crash. Existing A7 removal
  at both CALL boundaries and complete contiguous Ghidra Listing checks
  remain mandatory.

The model still accepts a **real two-edge convergent BNE** where both
source branches agree on the argument before the nested JSR, preserves the
distinct per-caller `SIMCR/CSBAR` candidate words and rejects hidden
P-code register clobbers as unresolved aliases. Tests deliberately include
fabricated one-edge BNE, forked BRA/NOP/MOVEA, duplicated successors,
incorrect JSR mnemonic, opcode/kind disagreements, out-of-range and odd
source PCs, recursion, and an agreeing positive branch.

Java21 deterministic suite and the full Java25/Ghidra 12.1.4 PUBLIC
extension plus real isolated synthetic two-hop/indexed/wrap headless CI
remain exact-SHA gates. Evidence is static **MAY** only: no executed
branch/CALL, SIMCR/MM latch, physical bus map, VBR/ISR activation, or
Review/Apply authorization. GA-02/03/18 remain PARTIAL.

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

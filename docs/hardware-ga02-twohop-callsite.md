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

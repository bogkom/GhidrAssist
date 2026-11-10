# GA-11 — statyczne kandydaty relokowanych tablic wektorów MC68332

## Podstawa dokumentacyjna

**MC68332 User's Manual**, Motorola ©1995, kopia udostępniona przez NXP:
https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf

- CPU32, **§5.2.5 Vector Base Register (VBR)**, **drukowana strona 5-6**,
  **fizyczna strona PDF 104**: VBR zawiera adres bazowy 1024-bajtowej tablicy
  256 wektorów. To opis architektury, **nie źródło aktualnego VBR ECU411**.
- CPU32, **§5.9.1 Exception Vectors**, **drukowana strona 5-13**,
  **fizyczna strona PDF 111**: wszystkie wektory poza początkowym RESET mają
  po 32 bity; tablica może być relokowana. RESET w CPU32 ma osobny przypadek
  przestrzeni supervisor program; relokowane bajty NIE dowodzą kolejnego RESET.

## Zakres implementacji

Po **jawnej** aktywacji profilu **MC68332**, dla każdej zdekodowanej
instrukcji `MOVEC ...,VBR`:

1. Rozwiązuj wartość źródłowego rejestru **tylko gdy poprzedniki CFG
   zgadzają się na jedną wartość**. `CALL_BARRIER`, niepełny Listing,
   nieznane skutki uboczne, aliasy i ograniczenia iteracji zachowują
   niepewność. Nie zakładaj wykonania rozgałęzień.
2. Pokaż funkcję, adres instrukcji, kandydat VBR, członkostwo w **statycznym
   podzbiorze grafu RESET** oraz flagi niekompletnego CFG i poprzedniego
   nieznanego CALL. `OUTSIDE_OBSERVED_RESET_CALL_SUBSET` oznacza tylko
   brak na zaobserwowanych ścieżkach — nie dowód nieosiągalności.
3. Dla **najwyżej trzech różnych** niezerowych lub zerowych kandydatów
   (w kolejności adresów) odczytaj tylko **obecne w Ghidrze bajty obrazu**
   z obszaru `VBR + 4 × vector` dla wektorów #2–#255.
   Sprawdź spójność 4-bajtowego wyrównania i całego 1024-bajtowego zakresu
   względem 24-bitowej przestrzeni MC68332. Nie śledź zawinięcia poza
   `0xFFFFFF`, nie przypisuj 32-bitowych wskaźników poza nią do
   fizycznych adresów MCU. Nieczytelne sloty pozostają UNKNOWN.
4. Istniejące `HardwareInterruptVectors` rozróżnia puste, nieparzyste,
   niezamapowane, dokładne wejścia funkcji i wskaźniki **do wnętrza**
   funkcji. `HardwareVectorResetCorrelation` nadaje tylko statyczną
   relację do ograniczonego grafu CALL. Nie promuj wskaźnika do wnętrza
   funkcji do potwierdzonego punktu wejścia ISR.

**Zasoby:** maks. 256 zaobserwowanych lokalnie instrukcji MOVEC w jednej
analizie, maks. 3 tablice, maks. 24 wiersze źródeł oraz po 12 wierszy
podglądu wektorów/relacji w tablicy. Pominięte instrukcje/bazy lub
niedostępne bajty są oznaczone jako **INCOMPLETE/UNKNOWN**, nie
`brak efektu`.

**Ograniczenia:** To źródłowe, odczytowe kandydaty tablic *w aktualnym
obrazie programu*. Wartość z CFG nie jest zatwierdzonym aktywnym VBR.
Statyczna osiągalność funkcji nie jest wykonanym RESET ani dowodem
przerwania, instrukcja MOVEC nie oznacza, że wykonano zapis, a bajty
programu nie są dowodem mapowania fizycznego po SIMCR/MM, CSBAR/CSOR
lub zmianach RAM. Nie zmieniaj danych, symboli ani projektów użytkownika.
Nie ma żadnej automatycznej operacji Review/Apply/Undo.

## Regresje

- `HardwareVbrRelocationEvidenceSelfTest` (Java 21): porządek,
  nieznane źródło, 4-bajtowe wyrównanie, granica 24-bit, maksymalne
  budżety, podzbiór RESET i brak fałszywego dowodu ISR.
- `vbr-relocation` w `Ga11VectorHeadlessMain`: **rzeczywista syntetyczna
  Ghidra 12.1.4 PUBLIC**, zdekodowane `MOVE.L #0x800,D0; MOVEC D0,VBR`,
  tablica źródłowa `0x800` z wektorami do funkcji na `0x400`, jej
  wnętrza `0x402` i adresem nieparzystym. Testuje odczyt,
  klasyfikację, nieaktywność profilu MCU w generic CPU32, zmianę
  bajtów tablicy, natywne Undo i brak zmian Program podczas analizy.
- GitHub Actions: pełna kompilacja rozszerzenia Ghidra 12.1.4 PUBLIC
  na Java 25, regresja Java 21, rzeczywista syntetyczna Ghidra headless
  na dokładnym commicie SHA, JSON/artefakty CI.

Stan GA-11 **CZĘŚCIOWO**: nadal brak dowodu rzeczywistej relokacji,
wykonywanej ścieżki ISR, złożonego pośredniego powiązania VBR
i sprzętowej akceptacji mapy magistrali.

## GA-11 source-provenance regression — 2026-11-04

The relocated MOVEC-to-VBR report must not label the correlated vectors as
`image-zero`. Previously the shared RESET/vector renderer hard-coded
`Vector table input: image-zero bytes ONLY` and
`Image-zero pointer`, even when invoked with a **nonzero relocated VBR
source-image candidate base**. That mislabeled where the already-readable
Ghidra bytes came from; it did **not** establish active IRQ.

The source renderer now accepts an explicit relocated source base, preserves
the original image-zero overload, rejects unaligned or 24-bit-overflow
bases, and retains the exact source table address in each read-only summary.
Both the generic vector inventory and the correlated RESET effect table use
`source-image` language for a nonzero candidate base. The classification,
function-entry distinction, reset reachability and side-effect uncertainty
remain unchanged.

Java 21 regressions assert distinct provenance labels without changing
classifications, and the existing isolated *real* Ghidra 12.1.4 PUBLIC
`vbr-relocation` headless mode now asserts the same on actual synthetic
MOVEC and table bytes, including MC68332 scope. It is **source-location
evidence only**, never proof that the MCU executed MOVEC or selected the
table. GitHub Actions PASS must be attached to this PR's exact commit SHA.
Stopped Wyse/Precision/Codex Supervisor tests remain stopped.


## 2026-11-10 — validated selected-MCU RESET source inventory before VBR ranking

The relocated `MOVEC` source-table planner uses `resetVisited` only
as a **ranking heuristic**, not proof of VBR selection or ISR execution.
Previously its source set was neither size-bounded nor validated even
though it can grant a MOVEC candidate a higher scan priority. It now
rejects null, negative, odd, and beyond-24-bit RESET function-entry
identities, and more than 50,000 RESET entries, **before** ranking
any tables. Invalid inputs are not tolerated even when the RESET root
is unrecognized. This gate applies only after the caller has explicitly
selected the MC68332 device profile; it does not cast a generic CPU32
32-bit function address into a speculative 24-bit physical bus alias.

Deterministic Java21 cases include normal and invalid RESET source sets,
UNKNOWN RESET root, wide/odd/null IDs, and oversized inventories.
No active VBR, ISA execution, actual interrupt, SIMCR/MM latch, physical
CS mapping, or program mutation follows from the source ranking.
GA-11/18 remain PARTIAL.

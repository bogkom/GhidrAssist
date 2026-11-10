# GA-02/03 — statyczne argumenty A/D w pojedynczym wywołaniu CALL

## Cel

Rozszerzyć źródłową analizę MC68332 o sytuacje, gdy funkcja wywołująca
ustala adres w rejestrze `A0..A7` i/lub wartość w `D0..D7`, a **konkretna,
bezpośrednio wywołana** funkcja używa tych rejestrów do potencjalnego
zapisu MMIO. Dotychczasowy `HardwareDataflow.analyze` rozpoczyna każdą
funkcję z nieznanymi argumentami i prawidłowo nie utożsamia funkcji z
jednym miejscem wywołania. To pozostaje domyślną, cache'owaną analizą.

Nowy odczyt to **dodatkowy, ograniczony raport kontekstowy**. Nie zmienia
semantyki oryginalnego raportu funkcji, źródłowych dowodów CSBAR, RAG,
Review/Apply/Undo ani etapów GA-12.

## Algorytm

1. Prawdziwy Listing/CFG Ghidry jest rozwiązywany w zwykłym trybie
   `HardwareDataflow`. Dla każdej instrukcji **bezpośredniego CALL do
   dokładnego początku funkcji** odczytywane są wyłącznie A/D wartości
   zgodne na wszystkich dochodzących poprzednikach z
   `Result.knownPointersAtEntry[CALL.pc]`. Nieznany cel, niedekodowane
   bajty, nierozwiązany skok lub ograniczony CFG nie są źródłem pewnych
   argumentów. Nie przypisuje się argumentów na podstawie ABI ani nazw.
2. Dla maksymalnie **96** odrębnych miejsc wywołania odczytaj funkcję
   docelową od jej punktu wejścia w Ghidrze. Wejście musi tworzyć
   **ciągły, kompletny Listing** do 128 instrukcji. Każde zagnieżdżone
   `CALL`, skok wyliczany, skok poza ciało, `CALLOTHER` albo nieznany
   blok uniemożliwia propagację kontekstową. Pominięcia/limity są jawne.
3. Dla jednej pary (CALL PC, dokładny callee entry) uruchom **osobny,
   niecache'owany** `HardwareDataflow.analyzeWithEntryRegisters`. Wszystkie
   istniejące instrukcje `SET/COPY/ADJUST/CLOBBER_POINTER`, operacje
   źródłowe `STORE`, maskowanie 24-bitowe, indeksowanie i zachowawcze
   łączenie wielu poprzedników pozostają bez zmian. Odmienne wartości
   A/D z dwóch miejsc CALL **nigdy nie są łączone** jako globalna
   właściwość callee.
4. W dodatkowym raporcie pokaż tylko **potencjalne źródłowe zapisy**
   z rozpoznanym adresem MMIO profilu MC68332 (lub nakładające się na
   niski bajt SIMCR). Brak wartości lub adresu pozostaje UNKNOWN.
   Nieznane aliasy są zliczane osobno; limit wyświetlania 96 wierszy
   oznacza `INCOMPLETE DISPLAY`, nigdy brak innych zapisów.

## Zabezpieczenie rejestru stosu A7 (pakiet two-hop)

`JSR/BSR` zapisuje adres powrotu na stosie. Wartość A7 rozpoznana
przed `CALL` **nie jest** tożsama z A7 na wejściu do wywołanej
funkcji. Oba tory — niniejszy `one-hop` i nowy `two-hop`
(`docs/hardware-ga02-twohop-callsite.md`) — jawnie usuwają A7
na każdej granicy CALL. Nie domniemają rozmiaru ramki, aktualnego
supervisor/user stack pointer ani fizycznej mapy MMIO na podstawie
przedwywołaniowego A7.

## Zabezpieczenia

- Analiza działa wyłącznie po **jawnej selekcji profilu MC68332**;
  generic `68000:BE:32:CPU32` nie oznacza urządzenia MC68332.
- Źródłowe `CALL` może nigdy nie zostać wykonane. Osiągalność CFG nie
  potwierdza przebiegu ECU ani aktywnego SIMCR/MM. Nie ma zgody na
  auto-Review/Apply; raport oznacza `SOURCE-ONLY MAY-CANDIDATES`.
- Dla nieznanego celu CALL, pośredniego aliasu, innej ścieżki z
  niezgodnym A0 lub niepełnego Listing **nie wymyślaj** adresu/arg.
- Korpusy wejścia są ograniczone do 96 CALL × 128 instrukcji callee;
  ponad limit lub przy zbyt wielu iteracjach wyniki są
  `UNKNOWN/INCOMPLETE`, nigdy bezwarunkowo prawdziwe.
- GA-12 per-function/disk cache nadal dotyczy **wyłącznie** standardowej
  analizy funkcji z nieznanymi rejestrami wejściowymi.
  `analyzeWithEntryRegisters` nigdy nie zapisuje wyniku do tego cache.
  Zmiana kodu źródłowego modułu powoduje ponowną kompilację
  i unieważnia istniejące dyskowe checkpointy według SHA-256 JAR.
- Brak zmian danych w projekcie, profilu użytkownika, firmware ECU411,
  OAuth lub ustawieniach zatrzymanego Supervisora.

## Weryfikacja

- `HardwareCallsiteRegisterFlowSelfTest`, Java 21: dwa niezależne
  konteksty (różne A0/D0 do tego samego callee), odrzucenie starego
  rejestru po CALL, rozbieżne poprzedniki branch, nieznany alias,
  pośredni/nieznany cel, incomplete callee, nested CALL,
  niedozwolone wartości poza `0xFFFFFF`, limit wierszy i wciąż
  nieznany adres w zwykłym `HardwareDataflow.analyze`.
- `Ga11VectorHeadlessMain`, tryb `call-context`: prawdziwa izolowana
  syntetyczna Ghidra 12.1.4 PUBLIC, instrukcje CPU32
  `MOVEA.L #0xFFFA00,A0; MOVE.L #0x40CA,D0; JSR callee`,
  drugie miejsce CALL z `0xFFFA68/0x4848` i callee
  `MOVE.W D0,(A0); RTS`. Test sprawdza różne źródła, brak promocji
  do globalnych `rawCfgMmioSites`, negatywny generic CPU32 i brak
  zmian `Program.modificationNumber`.
- GitHub Actions: Java 21 source, pełna kompilacja rozszerzenia z
  Ghidrą 12.1.4 PUBLIC / Java 25, rzeczywista syntetyczna Ghidra
  headless i dotychczasowe regresje niezależne na dokładnym SHA.

**Status GA-02/03: CZĘŚCIOWO.** Następnie możliwe jest sprawdzanie
ściśle ograniczonych wielopoziomowych ścieżek z formalnym
uzasadnieniem zachowania rejestrów, ale bez przenoszenia dynamicznych
wartości do globalnego dowodu Review/Apply.

## Aktualizacja limitów wejścia — 2026-11-04

Po integracji źródłowego one-hop/two-hop w `master`, oddzielny pakiet
utrwala limity również na **dekodowanych celach MMIO i callee**.
Dotychczasowe ograniczenie `96 CALL × 128 kroków` nie ograniczało
wprost liczby adresów przekazanych do `HashSet` ani liczby callee
zbudowanych przed analizą.

Oba tory teraz wymagają najwyżej **4096 wejściowych adresów** śledzonych
rejestrów; każdy adres musi być niepusty i należeć do przestrzeni
MC68332 `0x000000..0xFFFFFF`. One-hop dodatkowo wymaga najwyżej
**96 definicji callee**. Dane niepoprawne lub przekraczające limit
kończą wejście wyjątkiem walidacji zamiast produkować pozornie
wyczerpujący raport; **nie odrzucamy po cichu żadnego adresu**.
Poprawne istniejące wyniki i ograniczenia Review/Apply/Undo są
niezmienione. Jest to limit **wejścia analizy kontekstowej**, nie teza
o liczbie rzeczywistych rejestrów MCU, wykonaniu CALL czy fizycznej
mapie magistrali.

Java21 regresja sprawdza adres `null`, 25-bitowy i ujemny,
97 callee, dokładny próg 4096 oraz odrzucenie 4097 i izolację
wcześniej obliczonych wyników. Pełne CI i rzeczywista syntetyczna
Ghidra muszą zakończyć się PASS na końcowym SHA PR.

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

## 2026-11-10 — exact CPU32 MOVEQ signed register return across CALL (GA-02/03)

The existing read-only input-independent leaf-return verification now
supports canonical `MOVEQ #signed8,Dn` in addition to full-width
`MOVE.L/MOVEA.L` immediate definitions:

- `MOVEQ` writes **only D0–D7**, in exactly **two instruction bytes**.
  Its 8-bit literal is **sign-extended**, so `#-128` returns the
  source-proven `0xFFFF80` lower MCU24 register bits, not `0x000080`.
  An unextended/oversized synthetic operand, false A-register destination,
  missing fallthrough, hidden P-code register output or different instruction
  size is **not** eligible.
- A complete `MOVEQ; RTS` leaf is four bytes, rather than the old
  minimum eight for `MOVE.L #imm32; RTS`. The native isolated Ghidra
  decoder must still confirm the full function body, exact instruction
  lengths, direct CALL function identity, no nested call or CALLOTHER and
  no unsafe implicit register writes.
- The existing acyclic branch-return solver can carry signed `MOVEQ`
  values across Bcc/BRA only if **every** path to **every RTS** agrees.
  Divergent A-registers are downgraded to unknown without discarding a
  separate identical D0; cycles, RTE, conflicting bytes and phantom
  branch paths are refused.
- A signed return may yield a **static possible SIMCR STORE candidate**
  in the caller, but the prior unknown-CALL hazard remains explicit.
  No active MM latch, reached/executed CALL, physical bus mapping or
  Review/Apply permission is inferred.

Java21 straight-leaf and branch synthetic tests include sign bounds,
cross-CALL word `0xFF80`, and malformed negative cases. Genuine
Ghidra 12.1.4 PUBLIC headless acceptance now executes **both** the
existing `leaf-return` fixture and a new `moveq-return` fixture using
real CPU32 bytes, a four-byte positive `MOVEQ;RTS` and an `RTE` negative
control, with full extension build and read-only/generic-profile checks.
GA-02/03/18 PARTIAL; GA-14 deferred.

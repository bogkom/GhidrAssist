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

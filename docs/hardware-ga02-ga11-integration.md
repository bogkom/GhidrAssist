# GA-02/03 × GA-11 — wspólna weryfikacja statycznych źródeł CALL i MOVEC/VBR

## Cel integracji (PR #133 + #134)

Wspólna gałąź zachowuje oryginalne commity i CI obydwu pakietów:
- **#133** `2b0bf7d13dd9c4f352686f4f22d2952100300886` —
  źródłowe, ograniczone kandydaty relokowanej tablicy wektorów z
  `MOVEC ...,VBR`, korelowane z obserwowanym grafem RESET;
  **36/36 GitHub Actions SUCCESS** na tym commicie.
- **#134** `c833d612b8637236a426d0cc9cc62ce08389a603` —
  odrębne wartości A/D w poszczególnych bezpośrednich CALL oraz
  pomocniczy, nieutrwalany kontekstowy CFG callee; **40/40 GitHub
  Actions SUCCESS** na tym commicie.

Git `master` podczas przygotowania: `28b38252016625dbacae033d89dbc0191a7580cb`.
Wspólny PR nie jest upoważnieniem do automatycznego scalenia dużych
pakietów do `master`.

## Rozwiązanie zależności

Złączono w **jednym** `GhidraHardwareFlowService` oba kolektory:
- `vbrSourceSites` z niedynamicznego `MOVEC` i jego wartości
  rejestru przed instrukcją (z zachowaniem `unknownCall`,
  `uncertainFlow`, profilu MC68332 i ograniczenia źródeł).
- `callerContexts` z konkretnego `CALL.pc`, z osobnym, nowym
  wejściowym A/D dla zamkniętego callee. Stan ten **nie
  przechodzi do globalnego** `rawCfgMmioSites`, cache GA-12,
  RAG ani Review/Apply/Undo.

Wynikowy raport zachowuje niezależne, jednoznacznie podpisane części:
`Relocated VBR source-table candidates` oraz `One-hop CALL-site A/D
register and MMIO candidates`. Ich jednoczesne występowanie NIE
potwierdza, że VBR i zapis SIMCR były aktywne w tej samej sesji MCU.

Połączono także pełny `Ga11VectorHeadlessMain` i `run.py`;
ani `vbr-relocation`, ani `call-context` nie zostały pominięte.
Dodatkowy tryb **`joint-source`** otwiera **jeden rzeczywisty
syntetyczny Program Ghidry 12.1.4 PUBLIC**:
- dwaj różni callerzy przekazują do jednego callee różne argumenty
  `A0/D0` (SIMCR oraz CS);
- `MOVEC D0,VBR` wskazuje źródłową tablicę `0x800`,
  w której istnieje exact-entry, wskaźnik do wnętrza funkcji
  i nieparzysty adres;
- test wymaga obu raportów, poprawnych odrębnych wartości i
  klasyfikacji, oznaczenia niepewnego aktywnego VBR,
  zakazu przenoszenia CALLEE do globalnych dowodów Apply,
  negatywnego generic CPU32 i niezmienionej rewizji Program.

Wszystkie trzy tryby `call-context`, `vbr-relocation` i
`joint-source` wymagają pełnej kompilacji rozszerzenia Ghidry 12.1.4
PUBLIC z Java 25. Osobne testy Java 21 sprawdzają dokładne wejścia,
ograniczenia i fail-closed; dotychczasowe regresje GA-12 sprawdzają
checkpointy bez kontekstowych wyników.

## Zasady bezpieczeństwa

To **dowody statyczne z syntetycznego obrazu**. Dostęp do MMIO
i tablicy wektorów nie jest dowodem fizycznego MM, uruchomionego
VBR ani zrealizowanej instrukcji MOVEC/ISR. Wymagany jest
jawnie wybrany MC68332. Nie wolno testować na oryginalnym ECU411,
produkcyjnym projekcie, profilach ani OAuth. Testów
Wyse/Precision/Codex Supervisora nie uruchamiać bez nowej decyzji.

GA-02/03/11 pozostają **CZĘŚCIOWO**, GA-14 **ODŁOŻONE**.

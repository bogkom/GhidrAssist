# GA-18 — checkpoint integracji PR #97, 30.10.2026

**Jedyna macierz 48 PR (commit, funkcjonalność, zależności, CI, Wyse,
wymagania i braki):**
[PR #67 — komentarz #6519425856](https://github.com/bogkom/GhidrAssist/pull/67#issuecomment-6519425856).
Ta dokumentacja jest dziennikiem aktualizacji integracji, **nie**
drugą macierzą. Centralny indeks problemów technicznych pozostaje
w prywatnym Supervisorze [Issue #40](https://github.com/bogkom/codex-supervisor/issues/40).

## Wykonana integracja i dowody

Gałąź [PR #97](https://github.com/bogkom/GhidrAssist/pull/97) opiera się
na dokładnym, niezmienionym PR #77
`4b7a3aefe2a82fb572b8f7a79b5e8788d7425804`, zawierającym
stos #67→#68→#69→#71→#72→#73→#74→#75→#76→#77.
Przypięte stare commity pozostają nienaruszone.

**Kodowy commit `98aea7b75c18995308368b2bc4126b7a50647ebc`:
22/22 workflow GitHub Actions PASS**, w tym pełna kompilacja
Ghidry 12.1.4 PUBLIC (Java 25), rzeczywisty Ghidra ClassSearcher,
syntetyczne GUI CodeBrowser + Listing/stale guard + drugi proces JVM,
syntetyczne Query/policy Swing, strict-entry ISR w realnej Ghidrze
headless, modele CFG/CS oraz pełne regresje profilowe, CSV, PDF,
bitfield, analiza ograniczeń i współbieżność cache.

Przeniesione na zgodnych bazowych blobach:

- #82: MMIO zakres 16-bit, UNKNOWN zamiast zawijania liczby;
- #92 i #93: rejestracja PluginPackage oraz prawdziwy CodeBrowser harness;
- #80/#95: strict entry-vs-interior ISR i real Ghidra headless test;
- #83: numeric source-page SIMCR bitfield;
- #85: bounded ReAct findings/context;
- #87: adresowe rejestry wielokrotnego zakresu;
- #79→#91: PDF folio i overlong-text fail-closed;
- #81→#90: CSV formuły, limit wierszy, limit pól i `SOURCE_TRUNCATED`;
- #86: manifest case-fold / claims;
- #89: istniejący Query/policy Java Swing/Xvfb harness.

Zmiany wymagające **ręcznego połączenia fragmentów kodu**, a nie
kopiowania wcześniejszych plików:

- #78: dodano tylko bezpieczny read-only GUI porównania profili i
  model `HardwareProfileManifestComparison`;
- #88: poprawiono Overview truncation/NULL i dolne ograniczenia
  liczb, **zachowując** `withUnifiedSources()` z #72;
- #84: dostosowano generacje cache do nowszego
  `GhidraHardwareFlowService.analyze(program,monitor,selectedMcu)`,
  powiązano z `discardStale` i zachowano testy race.

#48: istniejący `HardwareApplyPlan` i SelfTest mają identyczne
bloby z oryginałem; `HardwareApplyService` ma późniejsze zmiany,
ale zachowuje `TPURAM_CANDIDATE` i etykietę. Nie zastępujemy
nowszego `HardwareAnalysisTab` dawnym GUI. #70 dotyczy dokumentacji
autoryzacji Supervisora, bez kodu produkcyjnego. #94 jest wcześniejszym
testem bazowego ISR; kryterium ostrzejsze pokrywa #95.

## Niezakończone bramki przed master

1. Przegląd łącznych zmian Review/Apply, CFG i kontroli rewizji,
   szczególnie między #77, #78, #84, #88 i poprawkami #82/#90.
2. **Jeden** odtwarzalny test rzeczywistego Ghidra Review/Apply
   i Undo na jednorazowym syntetycznym projekcie: sprzeczne CSBAR
   i alias UNKNOWN nie mogą tworzyć nieuprawnionego CS-window,
   Apply ma podlegać jawnej zgodzie i odwracalnej transakcji,
   oryginalny projekt/firmware/OAuth muszą pozostać nietknięte.
   Preferować istniejące testy GitHub Actions, a Wyse dopiero
   kiedy wymagany rzeczywisty GUI/Undo nie może być potwierdzony w CI.
3. Finalny build i regresje na dokładnym docelowym commicie oraz
   przegląd historii bazowej przy scalaniu do `master`. Nie tworzyć
   48 planów i nie żądać powtórzenia pokrytego testu per PR.

## Zachowane niezależne wyniki

- Formalny Supervisor PASS: #53 (headless), #54, #55.
- Realny manual GUI właściciela: #56 (ECU411 MMIO, SIMCR, Listing,
  blokada po zmianie programu); formalny stary Supervisor I/no ACK.
- Syntetyczny CodeBrowser na Wyse: #96 real host PASS;
  historyczny formalny workflow **WORKFLOW_CLOSED_FAILED**,
  wizualny odczyt/ACK **INCONCLUSIVE** (nie usterka parsera).
- Real-Ghidra headless syntetyczna na CI: #94, #95.
- Nie stwierdzono, że poprawiono stary przeniesiony profil Wyse,
  wykonanie ścieżek firmware czy fizyczny stan MCU.

**Źródła to commity, istniejące workflow i raporty.**
Późniejszy zielony CI nie konwertuje starszego wyniku Supervisora
w PASS. PR #97 pozostaje DRAFT i niescalony.

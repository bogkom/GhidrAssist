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

## Uzupełnione pokrycie — Review/Apply/Undo w rzeczywistej Ghidrze

Na bazie poprzedniego dokładnego HEAD `7af2bcbc0f0710153dcf9a156307b9712f00a7fb`
dodano wyłącznie testy na istniejącej integracyjnej gałęzi, **bez zmiany
żadnego przypiętego pierwotnego PR-a**:

- `f0d28c2ffe556334fc0fdd6cfd4e6a29acf54c4f`: prawdziwy produkcyjny
  dialog Review/Apply w pełnym Ghidra CodeBrowser na jednorazowym projekcie,
  Cancel bez zmian, domyślnie wybrany bezpieczny SIM, niezaznaczony
  spekulatywny TPURAM, ręczny wybór wyłącznie SIM, brak zapisu przed
  końcowym `YES`, rzeczywisty Apply w transakcji i Ghidra Undo.
  Dodatkowo negatywne, syntetyczne źródła: sprzeczne wartości CSBAR0,
  nieznany wskaźnik/STORE oraz niepełna analiza CFG — żaden z nich nie
  może wygenerować zaakceptowanego CS-window; jednoznaczny kandydat
  ma wyłącznie status `MANUAL_REVIEW`, nie automatyczny wybór.
- `9ce31ffe70d80f0804f6905fb3e847c08e17cea0`: runner wymaga
  jawnie `review_gui_cancel_no_change`,
  `review_gui_consent_and_undo_verified` i
  `conflict_alias_cs_windows_blocked` oprócz poprzednich asercji.
- [GitHub Actions #41041185455](https://github.com/bogkom/GhidrAssist/actions/runs/41041185455):
  **PASS prawdziwego syntetycznego CodeBrowser i produkcyjnego
  Review/Apply/Undo**; log zawiera `PASSED_SYNTHETIC_CODEBROWSER`
  i wszystkie trzy nowe pola. Artefakt wyłącznie syntetycznych logów:
  `12969679707`, SHA256 archiwum
  `3c134bf91487de08af5d509e1e29e254adda8199ef2255d6efa9fd61ba07bff4`.
  To nie jest formalny wynik Supervisora ani test rzeczywistego firmware.

## Niezakończone bramki przed master

1. Końcowy przegląd **łącznych produkcyjnych zmian** Review/Apply,
   CFG i kontroli rewizji pomiędzy #77, #78, #84, #88 i #82/#90.
   Dotychczasowy przegląd potwierdził, że ścieżka użytkownika żąda
   potwierdzenia, `HardwareApplyService` używa transakcji,
   a `HardwareCsbarUnifiedReview` odrzuca niejednoznaczne źródła;
   nie jest to podpis niezależnego recenzenta całego diffu.
2. **Test GUI/Apply/Undo na syntetycznym, jednorazowym projekcie: PASS CI**
   na commicie `9ce31ffe70d8`. Negatywne konflikty i aliasy są
   wstrzykiwane jako źródłowe obserwacje do produkcyjnego modelu;
   **nie** jest to potwierdzenie tych samych ścieżek na ECU411
   ani osobny interaktywny test właściciela na Wyse.
   Nie ponawiać testu Wyse PR #96 ani formalnego FAILED workflow.
3. Przed merge do `master` wymagana jest pełna kompilacja i
   regresje na **końcowym exact-head SHA** oraz świadomy przegląd
   historii bazowej. Nie tworzyć 48 planów ani nie powtarzać
   zaliczonych testów per PR.

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

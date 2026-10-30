# GA-18 — integracja GhidrAssist, plan oparty na macierzy 48 PR

Jedyna macierz testów PR→SHA→funkcje→zależności→CI→Wyse→pokrycie→brakujące
dowody jest zapisana przy istniejącym [integracyjnym PR #67, komentarz
#6519425856](https://github.com/bogkom/GhidrAssist/pull/67#issuecomment-6519425856).
Nie należy tworzyć drugiej równoległej macierzy w tym pliku ani w prywatnym
[Issue #40 Supervisora](https://github.com/bogkom/codex-supervisor/issues/40),
który pozostaje centralnym **indeksem usterek technicznych**.

## Decyzja integracyjna 2026-10-30

Gałąź tej zmiany zaczyna się od niezmienionego **PR #77**
`4b7a3aefe2a82fb572b8f7a79b5e8788d7425804`, który przejmuje
liniowy stos #67 → #68 → #69 → #71 → #72 → #73 → #74 → #75 → #76 → #77.
Kompilacje wszystkich wymienionych źródłowych PR przeszły swoje CI,
ale dowód z danego SHA nie jest dowodem testu nowej kompozycji.

**Bezpiecznie przeniesione bez konfliktu produkcyjnego:**

- Z PR #82 na bazie PR #56:
  `HardwareMmioExplorer.java` i `HardwareMmioExplorerSelfTest.java`.
  Pliki wejściowe w PR #77 miały **identyczne blob SHA** jak oryginalny
  PR #56; dlatego dokładna poprawka range `0..0xffff` i deterministyczny
  test granic mogą być przeniesione bez wymazywania późniejszych zmian.
- Z PR #92: `GhidrAssistPluginPackage`, jednoliniowy `packageName`
  i dwie klasy testowe oraz istniejący workflow ClassSearcher. Źródło
  `GhidrAssistPlugin.java` w PR #77 miało identyczny blob SHA jak
  oryginalny PR #56, więc nie nadpisaliśmy modyfikacji spoza tej poprawki.
- Z PR #93: **istniejący**, przetestowany Java/Swing CodeBrowser harness
  z testami Go To Listing, stale-program guard, zapisu `<EXTENSIONS>`
  i drugiego procesu JVM. Żadnego nowego frameworka.

**NIE przeniesiono bez weryfikacji konfliktów:** późniejsze boczne
PR #83/#84/#85/#86/#87/#88/#90/#91 ani zmian z PR #48 czy strict
ISR #80/#95. W szczególności #84 dotyka
`HardwareAnalysisTab.java` i cache, podczas gdy #77 rozwinął CFG.
Wymagane są selektywne łączenie i jedna finalna CI/regresja.

## Stan testowania

Bramki dla tego zakresu na **nowym exact-head SHA**:
`HardwareMmioExplorerSelfTest`, pełna Ghidra 12.1.4 PUBLIC extension
build, rzeczywisty ClassSearcher `PluginPackage`, syntetyczny
CodeBrowser MMIO/SIMCR Listing/guard oraz odtwarzanie konfiguracji w
drugiej JVM. CI automatycznie uruchamia istniejące workflow po dodaniu
ich plików; nie przypisujemy PR #77 wcześniejszego CI ZIP do tego SHA.

Nie wykonuj lokalnego testu każdego osobnego PR. Znane dowody to:
Supervisor formalne PASS #53/#54/#55; właścicielski manual GUI PASS #56;
realny syntetyczny CodeBrowser na Wyse PR #96 PASS, ale formalny PR96
workflow zamknięty jako FAILED z GUI INCONCLUSIVE/no ACK. Żaden taki
historyczny wynik nie został zmieniony.

Kryterium lokalne pozostające bez pokrycia to **rzeczywisty Review/Apply
z Undo** w izolowanej Ghidrze i (jeżeli wymagane) stary profil Wyse.
Najpierw używaj istniejących deterministycznych testów Ghidry CI.
Przed wejściem do `master` konieczny jest jeden końcowy wspólny build
na pełnym zestawie poprawek bocznych i przegląd zmian semantycznych.

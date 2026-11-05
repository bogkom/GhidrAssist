# GhidrAssist — 18-track hardware-analysis development ledger

Status: **IN PROGRESS — integrated baseline 2026-11-04**. Scope source: user-approved 2026-10-28 requirements (A–H, additional features 13.1–13.7, PDF/RAG, testing and Codex Supervisor integration).


## GA-01/11 — kandydat 2026-11-05: niepewność RESET w korelacji wektorów

W `HardwareVectorResetCorrelation` istniejące `flowUncertain` musi
uwzględniać również brak rozpoznanego korzenia RESET lub niekompletny
graf połączeń, nawet gdy lokalne poddrzewo wektora jest domknięte.
Zachowujemy adresy, relacje statyczne i niezależne kandydaty STORE/VBR.
Java21 i pełny build Ghidry 12.1.4 PUBLIC / Java25 wymagają PASS na
dokładnym SHA. Nie jest to dowód wykonania RESET/ISR.

## GA-01 — kandydat 2026-11-05: kolejka RESET i cykle CALL

Statyczny graf wywołań RESET ma odrzucać eksplozję powtórzonych ścieżek:
kolejka BFS harmonogramuje każdy bezpośredni cel tylko raz i pozostaje
ograniczona liczbą węzłów. Wykrywanie cykli jest niezależne od drzewa
najkrótszych ścieżek (Kahn); zbieżność ani zdublowana krawędź nie oznacza
rekurencji. Przekroczenie rozmiaru grafu lub kolejki oznacza
`TRUNCATED/UNKNOWN`, nie dowód braku SIMCR/VBR. Java21 i pełny build
Ghidry 12.1.4 PUBLIC / Java25 wymagają osobnego PASS na SHA PR.
Nie oznacza to wykonania RESET ani aktywnych przerwań.

## GA-12 — kandydat 2026-11-05: tożsamość właściciela epoki CFG

Odczytowe generacje unieważniania checkpointów mają być izolowane na
**konkretny obiekt Ghidra Program**, nie przez `equals()` współdzielony
przez dwa odrębne obiekty. `WeakHashMap` zastąpiono słabymi kluczami
identyczności z `ReferenceQueue`. Java21 testuje kolidujące `equals`,
niezależne unieważnienia oraz niezarejestrowanego właściciela. Czas życia
programu i wersja analizy nadal są weryfikowane osobno. CI i pełny
build Ghidry 12.1.4 wymagają odrębnego PASS na SHA PR. Nie oznacza
to wznowienia obliczeń między różnymi Program/JVM.

## GA-06 — kandydat 2026-11-05: źródła HTTPS w manifestach

Ograniczenie strukturalnego podglądu zewnętrznych profilów: zewnętrzny
`DOCUMENT` wymaga jednoznacznego URI HTTPS z hostem, bez userinfo,
Unicode bidi/niewidocznych znaków i osadzonych CR. Standardowy CRLF,
ścieżki kodowane procentowo i zapytania są zachowane. Nie jest to
weryfikacja źródła PDF ani wydania i nie wykonuje importu. Wymagane
Java21 regresje parsera i pełny build Ghidry 12.1.4 na własnym SHA.

## GA-02/03 — kandydat 2026-11-05: wspólny budżet CALL i memoizacja

Nowa, niezależna gałąź po scalonym #148: memoizacja odczytowych podsumowań
konkretnego celu CALL w obrębie jednego przebiegu oraz wspólny limit
**16 384 zaplanowanych adresów** obejmujący także nieznane cele. Wyniki
po wyczerpaniu budżetu pozostają jawnie `LIMITED/UNKNOWN`; nie są
negatywnym dowodem braku SIMCR/MM ani zgodą Review/Apply. Przewidziane
regresje Java21: współdzielone cele, dwa duże grafy z nieznanymi
krawędziami, utrata budżetu przed znanym MM, porządek deterministyczny,
niepoprawni callerzy. Wymagany odrębny PASS CI i pełna kompilacja
Ghidry 12.1.4 PUBLIC / Java25 na dokładnym SHA. Bez testów lokalnych
Wyse/Precision i zatrzymanego Supervisora.

## GA-13 — aktualizacja 2026-11-04 po scaleniu PR #146

Chroniony `master` po [PR #146](https://github.com/bogkom/GhidrAssist/pull/146):
`ab0c61afac00e164c9b5ce2916444e3c297c451b`.
Dokładny HEAD pakietu:
`873eccb278f635c7882617574a3bc3625bc9ff6d`,
**22/22 GitHub Actions SUCCESS**, w tym Ghidra 12.1.4 PUBLIC / Java25
z prawdziwym syntetycznym `FunctionManager`, transakcyjnym
GhidrAssist Apply/Undo/Redo i testem Java 21. Identyczne drzewa Git
przed i po scaleniu:
`687c1122c84480b03029b155c5e218e31378520d`.
Na osobnym SHA scalonego `master` zakończyły się
**3/3 GitHub Actions SUCCESS**, w tym pełna kompilacja rozszerzenia,
GA-12 rewizje i źródłowy test GA-13.

Dla GA-13 zaimplementowano w Program Options **wersjonowaną
informację o zatwierdzonej przez GUI operacji zmiany nazwy funkcji**,
zapisując ją w tej samej transakcji co `setName`; Undo/Redo
przywraca zarówno nazwę, jak i rekord. To **częściowe**
pochodzenie operacji, nie ustalenie autorstwa ani audyt wszystkich
edycji Ghidry, a hash jest kontrolą integralności, nie podpisem.

**Nowy kandydat testowy:** weryfikacja trwałości rzeczywistych
danych Program po **zapisie i niezależnym uruchomieniu Ghidry w
drugim JVM**, na tej samej syntetycznej bazie. Jeden przebieg
tworzy i zapisuje zatwierdzoną nazwę z rekordem, drugi bez
ponownego importu odczytuje Function/Options i sprawdza
brak skutków ubocznych odczytu. Testy `ga13-receipt-restart-headless`
wymagają własnego PASS na dokładnym SHA; nie traktować starego
Undo/Redo PASS jako dowodu trwałości po restarcie.

Issue #106 pozostaje otwarte bez komentarzy wymagających poprawy;
#98 jest osobną migracją CodeBrowser. Bez Wyse/Precision/legacy
Supervisor; wyłącznie syntetyczne dane Ghidry na Actions.
GA-01–GA-18 nadal rozwijane; GA-14 odłożone.

## Aktualny stan — 2026-11-04, scalony PR #145 i rozwój GA-13

GitHub `master` po właścicielsko zatwierdzonym [PR #145](https://github.com/bogkom/GhidrAssist/pull/145):
[`d77f679977645961673c7727074df105c027cd49`](https://github.com/bogkom/GhidrAssist/commit/d77f679977645961673c7727074df105c027cd49),
drzewo `07ae919f359abf3c928f7bc4db94e87875143ba1`
**identyczne** z przetestowanym PR HEAD
`9e1eec99d28919f8da2b9f3abafc6b901c2cb2de`.
Na HEAD **21/21 GitHub Actions SUCCESS**, w tym Java21, pełna
kompilacja Ghidry 12.1.4 PUBLIC / Java25 i rzeczywista syntetyczna
Ghidra headless; **na dokładnym scalonym master 2/2 GitHub Actions
SUCCESS**, osobno Java21 nazw/CSV i pełny build.

**Priorytet następny GA-13:** oparta na istniejącym `Review names…`
trwała, wersjonowana informacja o **konkretnej operacji nazwania
funkcji**, przechowywana w Ghidra Program Options i zapisywana
**w tej samej transakcji** co zaakceptowane `setName`.
Zawiera Function entry, przed/po, źródłowy import SHA (nie SHA
nowszego programu), rewizję przeglądu, statyczną rolę, zebrane
rejestry i licznik unikalnych miejsc zapisu. Odporny na niepełne
pola i zmianę formatu odczyt ma umożliwiać powiązanie Undo/Redo
z usunięciem/przywróceniem rekordu. Wpis przypisuje operację
GhidrAssist, **NIE** potwierdza autora ludzkiego/AI; hash jest
kontrolą spójności, nie uwierzytelnieniem.

Wymagane testy: Java21 deterministyczny codec i limit pól;
rzeczywista izolowana Ghidra 12.1.4 PUBLIC z dwufunkcyjnym
Apply, rollback, Undo, Redo i ponownym Undo; pełna kompilacja
rozszerzenia na **dokładnym nowym SHA**. Ten pakiet pozostaje
kandydatem do czasu weryfikacji CI. Nie rozszerza Review/Apply
uprawnień ani nie twierdzi o wykonaniu ECU411.

Issue #106 nadal otwarte (zero nowych komentarzy); Issue #98
osobna luka migracji starego CodeBrowser. Wszystkie GA-01–GA-18
pozostają rozwojowe, GA-14 odłożone. Wyse/Precision/legacy
Supervisor nie uruchomiono.

## GA-02/03 oraz GA-08/13 — 2026-11-04, po scaleniu PR #144

Na wyraźnej wcześniejszej zgodzie właściciela na bezpieczne scalanie
przetestowanych pakietów zamknięto
[PR #144](https://github.com/bogkom/GhidrAssist/pull/144)
z `merged=true`. Chroniony `master`:
[`30b1a9146b19939d884200648d545fb45797620c`](https://github.com/bogkom/GhidrAssist/commit/30b1a9146b19939d884200648d545fb45797620c).
Dokładny, przetestowany PR HEAD:
`406d4464efaf3ccf3ef55064b4244c46909ffe67`;
**20/20 GitHub Actions SUCCESS** (Java21, Ghidra
12.1.4 PUBLIC / Java25 i rzeczywista syntetyczna Ghidra headless).
Drzewa Git PR HEAD / merge są identyczne:
`cb7b23d97a20f46c4167847be0daf3d8979b37ac`.
Po scaleniu osobna pełna kompilacja na dokładnym merge SHA
**1/1 GitHub Actions SUCCESS** ([41885764324](https://github.com/bogkom/GhidrAssist/actions/runs/41885764324)).
GA-02/03 pozostają **CZĘŚCIOWO**: kolejka transytywnego grafu CALL
jest teraz limitowana również liczbą zaplanowanych i nierozpoznanych
węzłów; głęboka detekcja cykli nie przepełnia stosu Javy.
Wynik `LIMITED/UNKNOWN` nie wyklucza późniejszego STORE SIMCR/MM.

**Nowy, niezależny pakiet GA-08/13:** zabezpieczenie trzeciego
(starszego) eksportu CSV z podpowiedziami **ról wskaźników** przez
wspólny encoder komórek Review (limit 512 znaków, maskowanie
formuł/Unicode) oraz osobny limit 5000 wierszy z licznikiem
`OMITTED_ROWS` i znacznikiem `INCOMPLETE_EXPORT_NEVER_AUTO_APPLY`.
Nie tworzy automatycznych nazw, zatwierdzeń, rzeczywistej historii
autorów ani trwałego dziennika Undo; wymaga własnych nowych
regresji Java21/Ghidra 12.1.4 i **PASS na dokładnym SHA** przed
scaleniem.

Issue #106 nadal otwarte bez nowych problemów; Issue #98 pozostaje
osobną luką migracji starego CodeBrowser. Wszystkie 18 obszarów
nadal rozwojowe, GA-14 odłożone. Nie uruchomiono zatrzymanych
testów Wyse/Precision, timerów, sesji ani Supervisora.

## Aktualizacja GA-02/03 — 2026-11-04, po scaleniu #142 i #143

**Źródło stanu: GitHub.** Właściciel wcześniej zatwierdził scalanie
przetestowanych pakietów. [PR #142](https://github.com/bogkom/GhidrAssist/pull/142)
dotyczący ograniczonych wejść one-hop/two-hop został scalony do chronionego
`master` jako `98be5608eac121e1dcd141fb6db651724e5172ef`.
Zachowano identyczne drzewo Git PR i merge SHA
`394e47d945524bfb5291b677333d6e388bf05cf8`.
Dokładny PR HEAD: `e3384ed94940c781ac788feb5e04fe773d9cb89e`,
**21/21 GitHub Actions SUCCESS**, w tym Java21, pełny build
Ghidry 12.1.4 PUBLIC / Java25 i syntetyczna Ghidra headless.
Na dokładnym merge SHA: osobny **1/1 CI SUCCESS** (pełny build).

[PR #143](https://github.com/bogkom/GhidrAssist/pull/143)
zabezpiecza starsze eksporty CSV propozycji nazw rejestrów/funkcji
przed formułami ukrytymi znakami Unicode. Przeszedł **21/21 GitHub
Actions SUCCESS** na dokładnym HEAD
`935fa6b9efc6e6dc8470f10d06f0533512ae95b9` i został scalony
jako `4664e4d3e3a33ccf9b52c24a89d5a42533d6066d`.
Drugi merge dodaje tylko sześć plików PR #143 do #142; kontrola
blobów potwierdziła brak nadpisania plików źródłowych obu pakietów.
Po scaleniu końcowy SHA uzyskał oddzielny **2/2 CI SUCCESS**
(pełny build + Java21 nazwy/CSV). Te kontrole nie dowodzą
ruchu na ECU411 ani prawdziwego autorstwa zmian.

**Bieżący następny pakiet GA-02/03:** rozwiązać ryzyko nieograniczonej
kolejki transytywnego CALL w `HardwareInterproceduralMmEffects` przez
deduplikację i `maxCount` także dla zaplanowanych/nieznanych adresów,
oraz zastąpić rekurencyjne wykrywanie cykli iteracyjnym DFS.
Przekroczenie budżetu pozostaje jawnie **LIMITED/UNKNOWN**, bez
fałszywego wniosku o braku zapisów SIMCR/MM. Deterministyczne testy
Java21 mają obejmować szeroki graf, głęboki ciąg krawędzi, prawdziwy
cykl, wielokrotne wspólne cele oraz nieznane węzły.
**Przyszłego CI PASS nie wolno zakładać przed wynikiem na dokładnym SHA.**

Issue #106 pozostaje otwarte bez nowych wpisów. PR #98 zachowuje
oddzielną lukę migracji profilu CodeBrowser. GA-01–GA-18 nadal
nieukończone; GA-14 odłożone. Testy lokalne Wyse/Precision i
stary Supervisor pozostają zatrzymane.

## Kontynuacja GA-02/03 — 2026-11-04, po scaleniu #141

Chroniony `master` po właścicielsko zatwierdzonym PR #140 i
niewielkim, przetestowanym PR #141: merge SHA
[`703693c52fee4e300e2a896dba4b475262672459`](https://github.com/bogkom/GhidrAssist/commit/703693c52fee4e300e2a896dba4b475262672459).
PR #141 zachował zgodne drzewo źródeł i uzyskał **25/25 GitHub
Actions SUCCESS** na dokładnym HEAD oraz **1/1 SUCCESS** (pełna
kompilacja Ghidry) po scaleniu na dokładnym merge SHA.
Zależne #133–#139 zostały zamknięte administracyjnie po sprawdzeniu,
że ich commity są przodkami `master`. Historia i dowody nie zostały
nadpisane, nie wykonywano drugiego scalania.

Nowy pakiet GA-02/03 na osobnej gałęzi dodaje walidację wejścia
dla `one-hop` / `two-hop`: maksymalnie 4096 źródłowych adresów
rejestrów MC68332, brak `null` i adresów spoza przestrzeni 24-bit;
dodatkowo w `one-hop` maksymalnie 96 opisów callee. To ochrona
odporności i kompletności **kontekstu źródłowego**, a nie nowe
twierdzenie o wykonaniu CALL, rzeczywistym SIMCR/MM, VBR czy
fizycznym CS. Regresje obejmują progi i izolację wyników; **PASS
dla nowego SHA należy potwierdzić osobno**, nie na podstawie master.

Zależności dalej rozwojowe: wielopoziomowy GA-02/03, trwałe
Review/Apply/Undo i pochodzenie decyzji GA-08/13 oraz PDF
GA-06/10/16. GA-14 nadal odłożone, Issue #106 otwarte bez nowych
problemów; Wyse/Precision/legacy Supervisor pozostają zatrzymane.

## Aktualizacja master — 2026-11-04, po zatwierdzonym scaleniu PR #140

Na wyraźne polecenie właściciela [PR #140](https://github.com/bogkom/GhidrAssist/pull/140)
został scalony standardowym merge do chronionego `master`.
Commit scalający: [`73363ccd881efb976b0690857acb6157398b20d2`](https://github.com/bogkom/GhidrAssist/commit/73363ccd881efb976b0690857acb6157398b20d2).
Dokładny HEAD kandydata:
[`eccdc7ac7743533c2df7a6f477fe33367f247572`](https://github.com/bogkom/GhidrAssist/commit/eccdc7ac7743533c2df7a6f477fe33367f247572).

- **55/55 GitHub Actions SUCCESS** na kandydata SHA, w tym Ghidra
  **12.1.4 PUBLIC / Java 25**, Java 21, rzeczywista syntetyczna
  Ghidra headless z CALL/VBR/ISR i trwałym checkpointem oraz
  deterministyczne testy bezpieczeństwa.
- **Identyczne drzewa Git** na kandydacie i commicie scalającym:
  `4b7f55449acf6de0552532d91bed6e71522319d9`.
  Odrębne workflow `master` na **dokładnym merge SHA**:
  **11/11 GitHub Actions SUCCESS**, w tym pełna kompilacja rozszerzenia.
- Historia oryginalnych PR-ów **#133–#139** została zachowana w
  dwurodzicowych commitach integracyjnych. #135 obejmuje GA-02/03
  jednopoziomowy CALL i GA-11 MOVEC/VBR; #136 dwa poziomy CALL;
  #137 podpis checkpointu rozróżniający `null` i `-1`;
  #138 eksport CSV odporny na niewidoczne prefiksy Unicode;
  #139 właściwe pochodzenie tabel VBR zamiast etykiety image-zero.
  W testowym pliku Ghidry zachowano obie regresje CALL/VBR.
- **Wszystkie 18 obszarów pozostają rozwojowe** według kryteriów z tabeli
  poniżej; to rozszerzenie bazy GA-02/03/11/12/13, a **nie** dowód
  wykonania kodu na ECU411, aktywnego MM/VBR, fizycznego dekodowania CS
  ani ukończenia GA-01–GA-18. GA-14 wciąż odłożone.
- Issue #106 nadal otwarte (brak nowych zgłoszeń); Issue #98 to
  niezależna luka migracji starego profilu CodeBrowser. Nie wznowiono
  lokalnych testów Wyse/Precision, zatrzymanych workerów, timerów
  ani Codex Supervisora. Testy kolejnych zmian pozostają CI-first.

Punkt kolejnej kontynuacji: pogłębianie GA-02/03 statycznych przepływów
pośrednich rejestrów, bezpieczne checkpointy GA-12 oraz pochodzenie
Review/Apply/Undo GA-08/13; dokumentacja profilowa GA-06/10/16 z
wydaniem i stroną PDF.

## Historyczny stan — 2026-11-04, po kontrolowanym scaleniu PR #131

**GitHub = źródło prawdy.** [PR #131](https://github.com/bogkom/GhidrAssist/pull/131)
został scalony standardowym merge przez chroniony `master`,
z zachowaniem oryginalnej historii 13 PR-ów #118–#130.

- **Commit wdrożenia:** [`217a5dd43e48135cde930e6f14dcb9b879c12b23`](https://github.com/bogkom/GhidrAssist/commit/217a5dd43e48135cde930e6f14dcb9b879c12b23).
- **Dokładny HEAD kandydata:** `e182c0f2b1f49e13b1975727956d1dcc2347d32e`.
  **55/55 GitHub Actions SUCCESS**, w tym Java 21, kompilacja rozszerzenia
  Ghidra 12.1.4 PUBLIC / Java 25, rzeczywista syntetyczna Ghidra headless,
  Xvfb/CodeBrowser oraz Automation API na izolowanym projekcie.
- **Identyczne drzewa obu commitów:** `4279c8fbead2921d3d5814d635eef63f8908782b`.
  Zatem komplet zweryfikowanych plików jest dokładnie taki sam na
  scalonym SHA, bez odchyleń w konflikcie po stronie `master`.
  Na **dokładnym merge SHA** dodatkowo **22/22 push GitHub Actions SUCCESS**,
  w tym [pełna kompilacja Ghidry 12.1.4](https://github.com/bogkom/GhidrAssist/actions/runs/41834860451).
- [RESET / wektory / źródła ISR](https://github.com/bogkom/GhidrAssist/actions/runs/41833621753),
  [Review/Apply nazw + Undo / odrzucenie starej rewizji](https://github.com/bogkom/GhidrAssist/actions/runs/41833621858),
  [CALL → checkpoint i unieważnianie cache](https://github.com/bogkom/GhidrAssist/actions/runs/41833621715),
  [trzy JVM, częściowy fixed point CFG](https://github.com/bogkom/GhidrAssist/actions/runs/41833621809),
  [Automation API](https://github.com/bogkom/GhidrAssist/actions/runs/41833621839) i
  [rzeczywisty syntetyczny CodeBrowser pod Xvfb](https://github.com/bogkom/GhidrAssist/actions/runs/41833621737):
  **CI PASS** na HEAD kandydata — nie oznacza testu na oryginalnym firmware.
- GitHub oznaczył bezpośrednie PR-y #118, #119, #120, #121, #122,
  #124 jako `Merged`. Zależne PR-y #123, #125–#130 są **administracyjnie
  zamknięte**, ponieważ każdy ich HEAD jest już przodkiem `master`
  (GitHub compare: 0 commitów behind). Odrębne etykiety `Closed`
  w interfejsie nie oznaczają braku włączenia kodu.
  Ich oryginalne SHA, komentowane checkpointy i dowody CI pozostają.
- Starsze, historyczne PR-y spoza tego pakietu nie są automatycznie
  uznane za wykonane ani zamykane; Issue #106 nadal jest otwartą
  skrzynką problemów produktu, bez nowych komentarzy. Issue #98
  nadal wymaga odrębnego dowodu migracji starego profilu CodeBrowser.

**Statusy obszarów po integracji** (18 obszarów, nie 18 jednorazowych
testów; `BAZA_WDROŻONA` oznacza ograniczoną bazę, nie zakończenie):

| Obszar | Stan | Nowa potwierdzona baza w `master` | Kryteria nadal otwarte |
|---|---|---|---|
| **GA-01** RESET | CZĘŚCIOWO | Statyczna korelacja RESET z wektorami, ograniczony graf wywołań i warunki spójności | Niepełne skoki, analiza międzyfunkcyjna, brak śladu wykonania MCU |
| **GA-02** SIMCR/MM | CZĘŚCIOWO | Możliwe MMIO STORE, nakładanie bajtów SIMCR, 24-bitowe adresy, bounded CALL i stałe po RTS; **w nowym PR**: odrębne konteksty argumentów A/D dla jednego bezpośredniego CALL; **w zależnym PR**: bezpieczny, nieutrwalany łańcuch `CALL → bridge → CALL → MMIO` | Warunki pierwszego wykonanego zapisu / write-once, bardziej złożone wielopoziomowe ścieżki, brak dowodu aktywnego MM |
| **GA-03** pośrednie MMIO | CZĘŚCIOWO | CFG/P-code, indeksowanie, aliasy, bezpieczne unknown STORE, CALL-BARRIER i zgodność ścieżek; **w nowym PR**: potencjalne MMIO według argumentów ustalonych na konkretnym CALL PC (nie globalny Apply); **w zależnym PR**: jedno pośrednie CALL, rozbieżne gałęzie fail-closed i usunięcie A7 na obu granicach wywołania | Dalsze międzyfunkcyjne ścieżki, pośrednie CALL, niepełne dynamiczne aliasy |
| **GA-04** CSBOOT/CS | BAZA_WDROŻONA | Statyczna warunkowa tabela 12 okien z pochodzeniem źródłowym | Więcej konfliktów i wariantów CSPAR/CSOR; brak fizycznej mapy |
| **GA-05** Review/Apply/Undo | BAZA_WDROŻONA | Jawny preflight, bezpieczne zatwierdzanie, transakcje, Ghidra Undo, blokady niepewności | Rozszerzone scenariusze decyzji i uprawnień, bez automatycznego Apply |
| **GA-06** profile MCU | CZĘŚCIOWO | MC68332 wybierany jawnie, manifesty i sprawdzanie fizycznych stron PDF fail-closed | Zweryfikowane kolejne MCU i wydania dokumentacji z dowodami |
| **GA-07** analiza/raport/RAG | BAZA_WDROŻONA | Wersjonowany komplet źródeł, raport statyczny i eksport | Długie scenariusze i dalsza spójność wyników |
| **GA-08** nazwy | CZĘŚCIOWO | Propozycje funkcji, blokada nieaktualnej rewizji Apply, transakcja i Undo | Zmienne lokalne, argumenty i wskaźniki z Review/Undo |
| **GA-09** MMIO Explorer | BAZA_WDROŻONA | Read-only Listing i GUI CodeBrowser na syntetycznej Ghidrze w Actions | Dalsze przypadki GUI i rzeczywista migracja starego profilu (#98) |
| **GA-10** bitfieldy | CZĘŚCIOWO | Wybrane pola MC68332, konsekwentny dowód fizycznej strony i wydania | Pozostałe rejestry i ścisła walidacja pełnego korpusu |
| **GA-11** IRQ/VBR | CZĘŚCIOWO | Źródłowa korelacja wektor–RESET–funkcja i kandydaty ISR; **w PR**: ograniczony odczyt relokowanych tablic źródłowych wskazywanych przez MOVEC-to-VBR (zob. `docs/hardware-relocated-vbr-source-candidates.md`) | Dalsze pośrednie ISR, warunkowa relokacja i brak dowodu aktywnego IRQ |
| **GA-12** analiza przyrostowa | CZĘŚCIOWO | Ukończony CFG w RAM/dysku, per-function restart oraz bounded mid-function worklist przez JVM; SHA pełnego Program/JAR i CALL returns | Trwałość szerszych sesji i decyzji, więcej przerwań i wersjonowania |
| **GA-13** pochodzenie zmian | CZĘŚCIOWO | Rewizja zatwierdzonego Rename, SourceType, rollback/Undo | Trwała historia decyzji, autorów i powiązań zmian |
| **GA-14** firmware diff | ODŁOŻONE | Brak odrębnego porównania firmware | Schemat dowodów, Ghidra Version Tracking i izolowane porównanie |
| **GA-15** Agentic | CZĘŚCIOWO | Niepełne źródła pozostają oznaczone po pruningu findings-cache | Kontrola długich przebiegów, kontekstu i wznowień |
| **GA-16** PDF/RAG | CZĘŚCIOWO | Fail-closed fizyczne strony, wydanie i identyfikowalny dokument | Bardziej kompletne źródłowe korelacje rejestrów z PDF |
| **GA-17** testy/CI | CZĘŚCIOWO | 55/55 PR CI, 22/22 master push CI, realna syntetyczna Ghidra/Xvfb, JSON/JUnit/SHA | Dalsze scenariusze regresyjne, stary profil CodeBrowser #98 |
| **GA-18** automatyzacja | TOR_ZMIENIONY | Automation API v3 + agent CLI, kontrolowane GitHub Actions, CI-first integracja | Pełna autonomiczna orkiestracja i pomiar limitów wymagają osobnej decyzji |

**Niezmienne ograniczenia bezpieczeństwa:** statyczne P-code/Listing/CFG
nie dowodzą faktycznego wykonania RESET, zatrzaśnięcia MM, aktywnego
VBR/ISR ani rzeczywistej mapy magistrali. Generic CPU32 nie dostaje
automatycznie definicji MC68332; Profile/Review/Apply/Undo pozostają
kontrolowane. Dane oryginalnego ECU411, projekt Ghidry, profile i OAuth
nie były dotykane. Historyczne GUI/CUA/headless na Wyse/Precision oraz
worker, Goal i timery Supervisora **pozostają zatrzymane**.

**Następna praca**: konserwatywna analiza GA-02/03/11 przepływów
międzyfunkcyjnych i VBR/ISR; GA-06/10/16 zweryfikowane profile i
bitfieldy z wydaniem/stroną; GA-08/12/13 historia decyzji z Undo oraz
systematyczne pokrycie funkcjonalności przez GitHub Actions.
Nie traktować żadnego GA-01–GA-18 jako zamkniętego tylko dlatego, że
podstawowa funkcjonalność działa.

## Historyczny plan kompozycji — 2026-11-04 (przed scaleniem do `master`)

Kandydat `integration/ga01-ga18-reviewed-20261104` zachowuje oryginalną
historię i źródłowe dowody CI **wszystkich 13 zależnych/niezależnych
PR-ów #118–#130**, bez powielania ukończonych testów.
Punkt wyjścia: chroniony `master` `fda73ad65ff38c1c8030847a74e02a9d56d0afae`.

- Najpierw połączono statyczną analizę MCU `#122 → #123 → #126 → #128`
  z trwałym cache `#124 → #125 → #127 → #129` w PR #130.
  Wersja sygnatury funkcji `GA12-FUNCTION-CFG-FIXPOINT-2`
  obejmuje posortowane `verifiedCallReturns`; zmiana dowodu
  zwracanego rejestru unieważnia zarówno zapisane wyniki, jak i
  niedokończony stan CFG. Dokładny SHA PR #130:
  `21f250507e33c8452830e9438f8170ae954d2e12`;
  38/38 GitHub Actions SUCCESS.
- Następnie na osobnej gałęzi włączono PR **#118** z zależnościami
  RESET → wektory/ISR do wspólnego `GhidraHardwareFlowService`;
  `GhidraInterruptVectorService` dostaje rzeczywisty statyczny
  zbiór osiągalnych kandydatów, nie fałszywy ślad wykonania.
- Pakiety **#119** (zweryfikowane strony PDF, profile, bitfieldy)
  i **#120** (niekompletne źródła wyników Agentic) zachowują swój
  pierwotny zakres i historii SHA bez niepotrzebnych zmian.
- **#121** wymaga zarówno kontroli rewizji `HardwareAnalysisRevision`
  w `Review → Apply`, jak i regresji w tym samym testowym
  `Ga11VectorHeadlessMain`. Zachowano gałęzie `branch-cache`,
  `leaf-return`, `branch-leaf`, `function-stage-resume`
  oraz negatywną asercję `rename_stale_revision_blocked`.

**Brama do `master`:** najpierw otwarty PR integracyjny, następnie
kompilacja rozszerzenia dla Ghidry **12.1.4 PUBLIC / Java 25**,
regresje Java 21, rzeczywista syntetyczna Ghidra headless oraz
istniejące testy Xvfb/CodeBrowser/Automation API na dokładnym
commicie kompozycyjnym. GitHub Actions może wymagać ponowienia
**tylko infrastrukturalnie zablokowanego zadania** (np. Maven HTTP 429),
nigdy przenoszenia PASS z innego SHA. Dopiero po pozytywnych
wymaganych kontrolach i zgodnie z ochroną gałęzi możliwe jest
scalenie zatwierdzonego PR-a.

To nadal **częściowy zakres 18 obszarów**; zwłaszcza analiza RESET,
SIMCR/MM, CS, VBR/ISR i cache daje dowody statyczne, nie
potwierdza wykonania MCU ani fizycznej konfiguracji magistrali.
Issue #106 pozostaje skrzynką problemów produktu; Issue #98
zachowuje osobną lukę migracji starego profilu CodeBrowser.
Przerwane testy i workery Wyse/Precision/Codex Supervisora nie
są uruchamiane.

## Historyczna migawka PR-ów — 2026-11-04 (przed scaleniem #131)

**Stan przed scaleniem #131:** ówczesny `master` na
`fda73ad65ff38c1c8030847a74e02a9d56d0afae`.
Poniższe CI dotyczy **dokładnych commitów gałęzi PR**, nie `master`,
formalnej akceptacji Supervisora ani pełnego zamknięcia GA-01–GA-18.
Wszystkie obszary pozostają CZĘŚCIOWO lub ODŁOŻONE zgodnie z tabelą niżej.

| Pakiet | PR | CI PASS / wszystkie workflow na HEAD | Etap review |
|---|---|---:|---|
| RESET / wektory / ścieżki | #118 | 26/26 | osobny, nakłada się na `GhidraHardwareFlowService` |
| PDF / MCU / bitfieldy | #119 | 13/13 | niezależny |
| Agentic / kompletność źródeł | #120 | 2/2 | niezależny; pełna kompilacja w CI |
| Bezpieczne nazwy względem rewizji | #121 | 24/24 | wymaga dostosowania harnessu przy wspólnej integracji |
| SIMCR overlapping + modulo 24 bit | #122 | 24/24 | fundament GA-02/03 |
| Statyczne skutki CALL (unknown alias) | #123 | 24/24 | po #122 |
| Trwały ukończony etap CFG | #124 | 14/14 | fundament GA-12 |
| Ukończone funkcje w RAM | #125 | 26/26 | po #124 |
| Bezwarunkowe wartości po RTS | #126 | 27/27 | po #123 |
| Trwałe ukończone funkcje po restarcie | #127 | 29/29 | po #125 |
| Wszystkie ścieżki acyklicznego RTS | #128 | 28/28 | po #126 |
| Trwała niedokończona kolejka CFG | #129 | 28/28 | po #127 |

**Zależności:** GA-02/03: `#122 → #123 → #126 → #128`;
GA-12: `#124 → #125 → #127 → #129`. PR **#130** jest
odizolowanym punktem połączenia *obu historii Git*, z nowym SHA-256
`HardwareFunctionStageCache.signature` w schemacie `-2`, który
uwzględnia posortowane `verifiedCallReturns` i odrzuca stare
checkpointy po zmianie podsumowania funkcji wywoływanej.
Pełna integracja wymaga **własnego CI na finalnym SHA**.

**Ważne niekompatybilności do review:** #118 rozszerza wywołanie
`GhidraInterruptVectorService.analyze` i musi zostać zgodnie złączony
z interproceduralnym `GhidraHardwareFlowService`; #121 wymaga
`HardwareAnalysisRevision` przy Apply nazw i modyfikuje ten sam
syntetyczny harness `Ga11VectorHeadlessMain`. Nie wolno pomijać tych
zmian przez proste zastąpienie pliku.

**Tryb testowania:** tylko GitHub Actions na Ghidrze 12.1.4 PUBLIC
i Javie 21/25. Historyczne timery, GUI/CUA/headless na Wyse/Precision
i natywny Supervisor są zatrzymane decyzją właściciela. PR #98
zachowuje osobny brak testu migracji starego CodeBrowsera;
Issue #106 pozostaje otwartą skrzynką usterek (brak nowych zgłoszeń).
W chwili tej historycznej migawki `master` pozostawał niescalony;
wynik wdrożenia opisano w bieżącej sekcji wyżej.

## Stan historyczny — 2026-11-03, po integracji do `master`

**Punkt odniesienia:** `master` na commicie
[`2596a5a00e272720a091bc92209b00fb2edffefd`](https://github.com/bogkom/GhidrAssist/commit/2596a5a00e272720a091bc92209b00fb2edffefd).
To **aktualna ocena implementacji i dowodów**, nie zastąpienie historycznej
tabeli „Audited baseline 2026-10-28” ani zmiana statusu wcześniejszych testów.
Roadmapa ma 18 *obszarów*, a nie 18 jednorazowych testów.

**Słownik:** `BAZA_WDROŻONA` = główna, ograniczona funkcjonalność jest już
w `master` i ma regresje; **nie** oznacza pełnej realizacji wszystkich
kryteriów. `CZĘŚCIOWO` = istnieje kod i/lub testy, ale pozostają wymienione
wymagania. `ODŁOŻONE` = zakres celowo poza bieżącym priorytetem.
`TOR_ZMIENIONY` = historyczny workflow został zastąpiony, a nowa
operacyjna automatyzacja nie ma jeszcze pełnej akceptacji. **Żaden z
18 obszarów nie jest tu formalnie oznaczony jako zamknięty w całości.**

| Obszar | Aktualny stan | Potwierdzony zakres w `master` | Co pozostało / kryterium domknięcia |
|---|---|---|---|
| **GA-01** RESET i inicjalizacja | **CZĘŚCIOWO** | Wektor RESET, ograniczony graf wywołań i źródłowe hipotezy osiągalności | Bardziej kompletna analiza międzyfunkcyjna, niepewne skoki/wyjątki; nie nazywać osiągalności wykonaniem |
| **GA-02** SIMCR/MM i epoki rejestrów | **CZĘŚCIOWO** | Źródłowe STORE, możliwe lokalne pierwsze zapisy, warunkowe SIMCR/TRAMBAR/CS/VBR | Spójne stany ścieżek między funkcjami, nieznane efekty i ograniczenia MM write-once; bez twierdzeń o zatrzaśniętym MM |
| **GA-03** pośrednie MMIO / P-code | **CZĘŚCIOWO** | Bounded CFG/P-code, lokalne rejestry adresowe, aliasy i konserwatywne nieznane STORE | Pełniejsze indeksowanie/aliasy i bardziej zaawansowane przepływy międzyblokowe/międzyfunkcyjne; brak fizycznej mapy |
| **GA-04** CSBOOT i CS0–CS10 | **BAZA_WDROŻONA** | Warunkowa, 12-wierszowa tabela okien i bezpieczne dekodowanie CS | Weryfikacja nietrywialnych warunków CSOR/CSPAR, źródeł i konfliktów na dodatkowych przykładach; nie twierdzić, że okna są aktywne |
| **GA-05** Review/Apply/Undo | **BAZA_WDROŻONA** | Jawne zatwierdzenie, preflight, izolowane transakcje/Undo, blokady niepewnych CS | Dalsza akceptacja zaawansowanych scenariuszy na kopiach; polityka zapisu API w produkcji pozostaje wyłączona |
| **GA-06** profile MCU | **CZĘŚCIOWO** | Audyt źródeł MC68332, preview TSV, kontrola PDF SHA i porównanie *deklaracji* profili | Zweryfikowany import kolejnych MCU z wydaniem/manualem/bitfieldami; preview nie rejestruje urządzenia |
| **GA-07** Analyze/raport/RAG | **BAZA_WDROŻONA** | Trzyczęściowe Overview, Full Evidence i wersjonowany eksport | Sprawdzać spójność nowych analiz, skróty i kompletne dowody, bez podwójnego liczenia |
| **GA-08** propozycje nazw | **CZĘŚCIOWO** | Preview, bezkolizyjne zatwierdzane nazwy *funkcji* w jednej odwracalnej transakcji; źródłowe podpowiedzi A-register | Zmienne lokalne, argumenty i wskaźniki oraz ich niezależny Review/Undo; nie nadpisywać nazw ręcznych |
| **GA-09** MMIO Explorer | **BAZA_WDROŻONA** | Filtracja MMIO/Go To Listing, read-only z ochroną przed zmianą programu | Poszerzenie klasyfikacji i doświadczenia użytkownika na kolejnych wariantach danych |
| **GA-10** bitfieldy | **CZĘŚCIOWO** | Udokumentowane wybrane pola SIMCR z literalnych pełnych słów MC68332 | Pozostałe rejestry/pola, wydania i zerowe/nieznane reset values; bez dopisywania bitów bez źródeł |
| **GA-11** IRQ/VBR | **CZĘŚCIOWO** | Statyczny spis kandydatów wektorów i odróżnienie exact-entry od wnętrza funkcji | Analiza VBR/przemieszczenia tablic i zależności ISR; bez dowodzenia aktywnego IRQ |
| **GA-12** analiza przyrostowa | **CZĘŚCIOWO** | Identyfikacja rewizji Program, anulowanie, cache gotowego etapu CFG w bieżącym procesie | Trwałe checkpointy i wznowienie po restarcie, częściowe per-funkcja resume; kontrola unieważnienia |
| **GA-13** pochodzenie zmian | **CZĘŚCIOWO** | Aktualny Ghidra SourceType, preflight, lokalne CSV i ochrona eksportu | Rzeczywista trwała historia autorstwa zmiana→decyzja→Undo; SourceType nie identyfikuje człowieka/AI |
| **GA-14** porównywanie firmware | **ODŁOŻONE** | Brak porównywania dwóch firmware; istniejące porównanie *manifestów MCU* to GA-06 | Najpierw schemat raportu i Ghidra Version Tracking; potem bezpieczne różnice CS/VBR/peryferiów |
| **GA-15** Agentic | **CZĘŚCIOWO** | Istniejące Query/Agentic, ograniczanie kontekstu, polityki i wyniki źródłowe | Domknięcie długich przebiegów, cache/paginacji/przekazań oraz ocena regresji bez dublowania narzędzi |
| **GA-16** PDF/RAG | **CZĘŚCIOWO** | Strony fizyczne, niejednoznaczne folio, ostrożny odczyt kandydatów tabel, ograniczenia rozmiaru | Wiarygodne ekstrakcje tabel pól/offsetów z wersją źródła; odrębna walidacja strony drukowanej |
| **GA-17** testy / CI | **CZĘŚCIOWO** | 12.1.4 PUBLIC + Java, syntetyczne Ghidra/CodeBrowser/Xvfb, rollback i pakiety SHA | Niezależne testy zgodności starych przeniesionych profili, wybrane kopie ECU411 i dowody specyficzne dla nowych funkcji |
| **GA-18** Supervisor / automatyzacja | **TOR_ZMIENIONY** | Integracja opt-in Automation API v3, CLI, agent launcher; 10/10 wybranych testów Dell Precision, bez nowej pracy Supervisora | Zaprojektować API-first automatyczne wykonanie i raportowanie; historyczne GUI/headless Supervisora pozostają zatrzymane decyzją właściciela |

**Weryfikacja integracji:** PR
[#114](https://github.com/bogkom/GhidrAssist/pull/114),
[#115](https://github.com/bogkom/GhidrAssist/pull/115) i
[#116](https://github.com/bogkom/GhidrAssist/pull/116) są scalone;
końcowe `master` przeszło **11/11 workflow push SUCCESS**, w tym
[Ghidra 12.1.4 full build](https://github.com/bogkom/GhidrAssist/actions/runs/41694253605).
Wcześniejsze **10/10 wybranych hostowych testów Precision** dotyczyło
wyłącznie syntetycznego programu i określonego API — nie jest zaliczeniem
18 obszarów. Exact-head PR #114/#115/#116 miały odpowiednio
12/12, 13/13 i 14/14 CI SUCCESS; ich wyników nie należy przepisywać na
inne commity. `Issue #106` jest pustą otwartą skrzynką problemów,
a [Issue #98](https://github.com/bogkom/GhidrAssist/issues/98) zachowuje
osobną lukę testu migracji *starego profilu* użytkownika.

**Decyzja testowa 2026-10-31:** natywne GUI/CUA i headless timery
Codex Supervisora na Wyse zostały decyzją właściciela zatrzymane;
nie wolno zakładać ich ponownej aktywacji. Rozwój ma preferować
deterministyczne testy rzeczywistej Ghidry przez GitHub Actions/Xvfb
i nowe opt-in Automation API, z odrębnymi kategoriami dowodu
`CI`, `host-synthetic`, `manual-GUI`, `Supervisor-PASS`
i `INCONCLUSIVE/BLOCKED`.

**Priorytety dalszej realizacji:** (1) GA-01/02/03/11 — dokładniejsze,
ale nadal *statyczne* przepływy MCU; (2) GA-06/10/16 — weryfikowalna
wiedza o rejestrach; (3) GA-08/12/13 — bezpieczna edycja i trwałość;
(4) GA-14 — dopiero po zamknięciu schematów dowodów i akceptacji.
GA-17/18 to **metoda testowania wszystkich tych zadań**, a nie
osobna obietnica, że samo API automatycznie je zaimplementuje.

---

## Immutable engineering rules

- Ghidra target: **12.1.4 PUBLIC**, baseline for this work: `fix/hardware-analyze-focused-report-20261028`, commit `412448166ec5d9cc3750ee10d1ec215804ae5802` (draft PR #52), which itself builds on `codex/agentic-policy-and-evidence-fixes`. Do not substitute old `master` as a new-feature baseline without reconciling these changes.
- Preserve independent draft PRs #48–#50 and their local unpushed work. Reconcile overlap and obtain verification before closing or merging.
- **Static reachability ≠ execution**. Instruction-address order ≠ runtime order. MM may be write-once. Unknown call side effects and aliases must invalidate unjustified value claims.
- MCU-dependent information is conditional on a **manually selected, documented device**, never silently inherited by generic CPU32.
- Analyze is compact. Detail/uncertainty belongs in dedicated views; complete register catalog and explicit, undoable changes belong in Review / Apply.
- Public repository and Actions must never contain ECU411 firmware or its Ghidra project. On-host test copies only. Test artifacts contain non-sensitive summaries/hashes.
- GitHub Actions first; Supervisor plans pinned to immutable full 40-character commits. **Standing owner authorization for standard GA-01..18 local tests is already active on Wyse**, with revocable, fail-closed Supervisor policy; no new per-plan approval is necessary. Tests run only inside the approved dedicated test Goal/workspace, never a new Codex programming session.

## Scope mapping — exactly 18 tracked workstreams

The originating document has 18 *sections*, not 18 independent feature checkboxes. To avoid dropping any feature, the 18 implementation tracks below explicitly cover A–H, 13.1–13.7, RAG, verification, and autonomous test delivery. Section numbers 1–4 and 14,17,18 supply requirements and constraints across the tracks.

| ID | Source | Deliverable | Audited baseline 2026-10-28 | Acceptance / evidence |
|---|---|---|---|---|
| GA-01 | A | Reset vector / entry evidence and reachable initialization flow | PARTIAL INTEGRATED: image-zero RESET candidate, bounded direct-call graph and statically recognized function set; no dynamic path proof | Validate vector bytes / entry, distinguish reachable/candidate/unknown |
| GA-02 | B | Path-conditional SIMCR/MM (write-once), TRAMBAR, CSBAR/CSOR/CSPAR and VBR epochs | PARTIAL INTEGRATED: per-function SIMCR/MM, TRAMBAR, CSBAR/CSOR alternative words and unknown writes; no first-executed write or latched MM proof | Branch/alias/call uncertainty preserved, addresses and source paths |
| GA-03 | C | Indirect MMIO via A/D registers, indexed modes, P-code LOAD/STORE, aliases | PARTIAL INTEGRATED: conditional CSBOOT–CS10 table and source-local CS register alternatives; no physical bus map | Synthetic alias joins, call barriers, no invented constants |
| GA-04 | D | Per-select CSBOOT, CS0..CS10 table in Analyze | PARTIAL: decoder/windows exist; Markdown currently uses per-window bullets | 12 separate rows, start/end/size, missing values UNKNOWN, model scope |
| GA-05 | E | Safe CPU32-unknown vs model-specific Review/Apply | PARTIAL: MC68332 full catalog; unknown-mode review constrained | No model-inherited unsafe maps; collision/transaction/Undo tests |
| GA-06 | F | Extendible sourced MC683xx profiles and conflict matching | PARTIAL INTEGRATED: profile citation audit, strict preview-only external manifest and optional local PDF checksum; no verified MCU import | Explicit model/version/page/bitfields/reset source; SVD/RDL feasibility |
| GA-07 | G | Compact 3-part Analyze: initiation, register history, CS map | PARTIAL INTEGRATED: three-part Overview, full evidence tab and complete export/RAG evidence | UI/Markdown/RAG agreement, concise report, evidence links |
| GA-08 | H | Function, pointer and variable naming proposals | PARTIAL INTEGRATED: function naming review and source-only A-register role hints; no local-variable rename | Collision-safe preview, manual labels preserved, transactional Undo |
| GA-09 | 13.1 | MMIO accesses explorer with navigation | PARTIAL INTEGRATED: searchable read-only MMIO explorer with Go To Listing; host GUI verification pending | Filterable function/instruction/value/access/confidence with Go To |
| GA-10 | 13.2 | Verified bitfield decode with provenance | PARTIAL INTEGRATED: sourced SIMCR bitfield values from literal full-word writes only; other bits UNKNOWN | Unknown fields UNKNOWN; model- and edition-specific source |
| GA-11 | 13.3 | Interrupt / exception analysis including VBR and ISR paths | PARTIAL INTEGRATED: reset-based vector candidate inventory; actual VBR/ISR execution UNKNOWN | Static candidates not treated as active IRQs |
| GA-12 | 13.4 | Resumable, version-aware incremental analysis | PARTIAL INTEGRATED: revision-aware invalidation, cancelable Analyze and in-memory complete CFG-stage checkpoint | Program identity, input hash, invalidation and resume regressions |
| GA-13 | 13.5 | Human/analysis/AI origin of changes | PARTIAL INTEGRATED: read-only SourceType audit and local CSV; human/AI authorship UNKNOWN | Check actual Ghidra 12.1.4 SourceType API; retain rationale and Undo |
| GA-14 | 13.6 | Firmware configuration comparison | DEFERRED by source priorities | Assess Ghidra Version Tracking first; later CS/VBR/peripheral diff |
| GA-15 | 13.7 | Agentic planning, indirect calls, context, pagination, stale cache | PARTIAL: draft PR #49/#50 overlap and existing Agentic work | Don't duplicate existing tools; budget/policy evidence regression |
| GA-16 | 15 | Physical PDF page/printed label, register tables, sourced RAG | PARTIAL INTEGRATED: physical PDF-page and candidate printed folio sequence status; actual PDF source page remains authoritative | No auto-promotion of ambiguous PDF rows; page/edition evidence |
| GA-17 | 16 | CI, synthetic tests, isolated ECU411 project acceptance and rollback | PARTIAL: pure-Java Actions and private firmware tests exist | Compile 12.1.4, record artifacts/hashes, reversible actual-Ghidra test |
| GA-18 | 17 + new decision | GitHub-controlled multi-stage local Supervisor tests | OPERATIONALLY ACTIVE on Wyse as of 2026-10-29; PR #9 GitHub integration still open; real tests PR #53/#54/#55 PASSED | Pinned JSON, active standing authorization, quota safeguards, verified private reports |

## Dependency order and milestones

1. **Foundations/compatibility**: GA-17/GA-18, reconcile PR #48–#52 without disrupting installed #52; map existing Java APIs and tests.
2. **Reliable memory evidence**: GA-04 (initial deterministic table), GA-02/GA-03 (path state), GA-10 (bitfields), GA-05/GA-06 (device-scoped definitions). No false dynamic maps.
3. **Reset-rooted analysis**: GA-01, GA-11 and their prerequisites; then GA-07 combines initialization/history/map without dumping all registers.
4. **Investigation and safe edits**: GA-09, GA-08, GA-13; independent transactional and GUI regressions.
5. **Documentation and agent workflows**: GA-16, GA-15, GA-12; retain report provenance and avoid model token use for deterministic checks.
6. **Later comparison**: GA-14 after a stable report schema and Ghidra Version Tracking evaluation.

Each milestone: focused Java tests -> exact 12.1.4 extension build on GitHub Actions -> immutable candidate commit -> queue plan in private Supervisor repo -> fail-closed execution under the **already active standing owner authorization** -> verified isolated-Ghidra regression -> review and merge. A queued or artifact-verified plan is not PASS. Do not merge on planned rather than observed test results.

## First implementation batch

GA-04: add a pure, deterministic Markdown representation of the twelve MC68332 chip selects using the existing `ChipSelectModel.Window` decoder; unknown CSBAR/CSOR/CSPAR stays UNKNOWN. Integrate only as a **conditionally decoded** table in existing Hardware Analyze evidence, without claiming actual execution sequence, external wiring or firmware-derived active bus cycles. Keep all Review/Apply entries untouched.

For upcoming steps prepare independent Supervisor plans, each pinned to the corresponding **post-commit** GhidrAssist SHA. Do not queue speculative hashes or untested mutable refs.

## Explicitly deferred, not lost

Full MCU/peripheral emulation, physical CS electrical simulation, generic automatic hardware identification, and broad multi-firmware comparison remain out of the initial delivery, as required by original section 14.


## 2026-10-29 — GA-12 revision-aware read-only evidence (partial)

- New independent draft: `feature/hardware-versioned-analysis-cache-20261029`
  based on immutable PR #53 head `bd0a0a60eaa610e19581bd67fd16d29c637bfb8e`.
- Ghidra 12.1.4 `DomainObject.getModificationNumber()` changes on program
  edits, Undo and Redo; exact active Program object, language, original-import
  SHA-256 metadata, MCU profile selection and analyzer schema are part of
  the current scan's version check. Original SHA is *not* a live byte hash.
- Discard results if the source changes during asynchronous Analyze;
  do not publish stale RAG evidence. Invalidate cached hardware context on
  program edit/Undo/Redo, and refuse stale export/navigation/Review/Apply.
- When Analyze is repeated on an identical completed in-memory revision,
  reuse existing results without re-running the scan. This is a limited
  incremental optimization, **not** disk-backed resume or partially resumed
  CFG analysis. Those remain GA-12 TODO.
- CI: strict revision pure-Java regression plus complete 12.1.4 extension
  build; separate approved Supervisor real-Ghidra test required before merge.


## 2026-10-29 — GA-12 completed CFG stage resume and cancellation

- Draft branch `feature/hardware-resumable-cfg-stage-20261029`
  builds on immutable PR #60 head `a0dd587b8f60d47afdbf1a9725b6e0039dc87456`.
- A completed conservative CFG/P-code stage is cached first, keyed by exact
  Ghidra Program weak identity, analyzer schema, revision/Undo counter,
  language, original-import SHA-256 metadata and selected MCU profile.
- A later cancelled read-only inventory scan leaves the **completed** CFG
  stage available for same-revision retry. No half-processed function is
  interpreted as completed. A changed program/profile never reuses it.
- Analyze now supplies a real cancellable Ghidra TaskMonitorAdapter and
  Cancel Analyze button. Cancel never publishes partial RAG/Markdown/Apply
  evidence. Computed/reused checkpoint is labeled in completed report.
- This is **process-local completed-stage reuse**, not persistent disk
  checkpoints, interrupted-function continuation or cross-session resume.
- Gate: exact Ghidra 12.1.4 extension build and standalone negative stage
  tests, then local isolated Ghidra cancellation+Undo tests before merge.


## 2026-10-29 — integrated release candidate PR #67

- Branch `integration/hardware-tracks-20261029` is built on immutable
  PR #64 (and PR #60) and reconciles sibling PR #54–#66 functionality.
  It is a **draft integration candidate**, not a merge to `master`.
- Dedicated read-only RESET graph produces a set of recognized candidate
  direct-call functions, with recursion, unknown target and traversal caps
  preserved. The same immutable evidence is used for GA-01/02/03
  per-function write alternatives.
- Separate candidate word values for SIMCR/MM, TRAMBAR, CSBAR/CSOR/CSPAR
  are not interpreted as temporal register epochs. Chip Select state
  across functions or branch alternatives remains UNKNOWN.
- Compiles the full extension for Ghidra 12.1.4 and runs standalone
  adversarial tests. A green CI run is **not** local firmware acceptance.
  Prepare an *integration-specific*, artifact/SHA-pinned Supervisor plan
  after successful final-head CI; retain all old plans without automatic
  approval. Do not merge before real host integration verification.


## 2026-10-29 — GA-02/03 CFG-derived MMIO store evidence (#68)

- Independent dependent draft `feature/hardware-cfg-mmio-evidence-20261029`
  based on exact integration PR #67 SHA `85352509cd2de2e2dcc452eaf93c9ad49bedd0be`.
- A new source-only CFG/P-code report classifies resolved direct vs indirect
  register stores, full 16-bit literals, byte/long/unknown writes, and
  unknown-destination pointer aliases. It is separate from the direct
  Listing/XREF history to avoid double-counting as real execution.
- SIMCR write sites retain a saturated predecessor candidate range
  (0/1/2+) from within the modeled **same-function** CFG.
  Unknown calls, alias stores or control-flow limits force UNKNOWN,
  regardless of source-PC ordering or MM literal value. MC68332 MM bit
  is never declared a latched hardware configuration.
- New deterministic adversarial regressions and a full Ghidra 12.1.4 build
  required. No Review/Apply or Ghidra project modifications introduced.


## 2026-10-29 — GA-01/02/03 bounded within-function path possibilities

- Stacked draft `feature/hardware-cfg-store-path-relations-20261029`
  is based on exact PR #68 head `5b343d6da75f59785e1d3107dc42789a77be2565`.
- Read-only CFG pairwise path-existence between source sites for SIMCR,
  TRAMBAR, CSBAR/CSOR/CSPAR, bounded to 12 candidate writes per
  function and 1500 graph nodes per reachability query. The possible
  relations are A→B, B→A, both directions via cycles, no *modeled*
  connecting path, or UNKNOWN when budget is exceeded.
- Explicitly does **not** claim actual execution, feasible branch
  conditions or a unique chronological order after RESET.
- Generic CPU32 now suppresses concrete MC68332 register labels
  in the new CFG provenance table (addresses stay visible as hypotheses).
- Dedicated synthetic regression, full Ghidra 12.1.4 extension build
  and explicit host integration acceptance remain mandatory.


## 2026-10-29 — GA-01/02/03 read-only source-evidence CSV (stacked)

- `feature/hardware-initialization-evidence-csv-20261029` based on
  immutable PR #69 head `839767b3b688d3875a5f7a5481935269b95f1291`.
- Ghidra Hardware Analysis adds `Evidence CSV...`: separate,
  stable-schema, source-only STORE and CFG_PATH receipts, each
  `NEVER_AUTO_APPLY`. No accidental re-use as naming proposals.
- Export requires the identical current program revision and selected
  profile; profiles/edits invalidate old evidence. CSV injection guarded;
  file capped at 5000 records with omitted-row marker.
- Standalone schema regression + full Ghidra 12.1.4 build required.
  Real GUI and Undo/Redo acceptance remain pending Supervisor approval.


## 2026-10-29 — GA-01/02/03 unified source-site reconciliation (PR #72 candidate)

- Stacked branch `feature/hardware-unified-startup-evidence-20261029`
  based on immutable PR #71 head `bd206954ad9ca73f81804f836dd764e7729d3a6c`.
- Full-report startup alternatives now use a union of existing
  Listing/XREF candidates and CFG/P-code resolved direct/indirect stores,
  deduplicated by function+instruction PC+register-address.
- Each site carries independent LISTING/CFG origins; contradictory
  register identity, width, or literal degrades to UNKNOWN. Unknown
  destination aliases are counted as potential ANY-MMIO effects
  without inventing a specific register target. Byte/long/unknown
  writes never become confirmed 16-bit words.
- Generic CPU32 register labels in the new merged report stay
  UNVERIFIED_MCU_REGISTER. Source groups are still **static candidates
  only**, not execution events, proven reset epochs or physical CS maps.
- Deterministic synthetic conflicts/alias/duplicate tests and complete
  Ghidra 12.1.4 extension CI required before a pinned host plan; no
  changes to original program, RAG documents or user secrets.


## 2026-10-29 — GA-07 unified evidence summary without double-counting

- Three-part Overview remains compact, but section 2 now separately
  records unique function/PC/address source sites from both Listing/XREF
  and CFG/P-code, raw observations, deduplicated matches, conflicting
  candidate values and unknown-pointer aliases.
- Existing Listing count is deliberately not relabeled as runtime
  writes, and compiled CFG-only stores are not silently folded into
  historical Listing counts. No false execution or memory-map claims.
- Added pure Java summary/regression and full Ghidra build gate.

- Robustness follow-up: width=0 unmodeled P-code STORE now means
  UNKNOWN-width alias, rather than throwing an exception during a
  real Ghidra CFG pass. Synthetic regression covers this case.


## 2026-10-29 — GA-02/03 no lexical last-write-wins CS map

- The earlier per-function MM0/MM1 conditional CS table used a lexical
  address-ordered `Map.put` that could accidentally select the last
  source site even across branch alternatives.
- A standalone pure-Java source-consensus gate now includes a register
  only when **all observed candidate writes** have the same known
  full-word literal. Any different literal, partial-width or unknown
  write excludes the register and counts the conflict/unknown.
- The table remains a *conditional source sketch*, never a physical
  Chip Select configuration. Regression tests cover repeated agreeing
  literals, conflicting SIMCR values, unknown CSOR writes and
  reference-only sites. Full Ghidra 12.1.4 build gate remains.


## 2026-10-29 — GA-05 guarded CSBAR Review/Apply proposals

- Dependent branch `feature/hardware-csbar-review-gate-20261029`
  starts from immutable PR #72 head `f18904bd28fa7ff746b0ae7b5083671203f895e8`.
- Previously the Review/Apply CSBAR window source accepted every
  individual literal in the inventory, including MM0-addressed sites
  and contradictory assignments in alternative branches/functions.
- A conservative read-only gate now recognizes only exact MC68332 MM1
  source addresses for CSBARBT and CSBAR0..CSBAR10, requires a known
  full-word literal, and excludes a register entirely if any matched
  MM1 source disagrees or has an unknown write. Repeated agreeing
  sources result in one candidate, never a runtime event.
- The existing explicit user Review, Ghidra preflight, transaction and
  Undo semantics remain untouched. No automatic Apply is enabled,
  no reset-state or external CS activation is asserted.
- CI: pure Java negative safety tests and full Ghidra 12.1.4 build;
  local isolated GUI acceptance remains required before merge.


- GA-05 safety follow-up: absent `CS_WINDOW_*` proposals now
  receive `MANUAL_REVIEW` and `selectedByDefault=false`, not
  `READY` and automatically selected. Explicit operator selection
  and final confirmation are still necessary; existing preflight
  and Undo support are retained.


## 2026-10-29 — GA-05 Review proposals now consume unified CFG+Listing safety

- Stacked draft from PR #73 (immutable SHA `7b008b63c54c326023179b341e3d8d822736d868`).
- Read-only `HardwareCsbarUnifiedReview` consumes deduplicated Ghidra
  Listing + CFG/P-code candidate stores, rather than the historical
  Listing-only collection. Conflicting words, byte/long/unknown-width
  writes or unknown call/path hazards poison the affected register.
- An unresolved P-code pointer alias to an UNKNOWN destination may
  address any CSBAR; **all CSBAR memory-window proposals are suppressed**
  until a clean scan without such aliases. Generic CPU32 emits none.
  This may reject safe possibilities but never fabricates hardware state.
- The filtered immutable result is captured with the completed, versioned
  Analyze snapshot and is the only source used by Review/Apply.
  The source-gate status is visible in the Review dialog. Existing manual
  CS_WINDOW default and Ghidra Undo remain unchanged.
- Full Ghidra 12.1.4 build and synthetic safety checks required;
  real isolated host GUI acceptance remains pending.

- GA-05/13 review hardening: the revision token now guards local
  provenance CSV export before/after file dialogs, and guards Apply
  again **after** the final modal user confirmation. Same-Program
  identity alone is insufficient after Ghidra Edit/Undo/Redo.


## 2026-10-29 — GA-12 bounded CFG evidence capture, conservative Review

- Stacked on PR #74 exact head `68b665aa142f198745a08c0d7293dbedd7f43574`.
- Read-only CFG MMIO and A-register pointer-role source collectors
  now retain at most 12,000 and 8,000 records respectively, with
  explicit exact counts of discarded source sites.
- If the CFG walk or its source collector is incomplete, the unified
  CSBAR Review gate deliberately exposes **no speculative external
  CS-window proposals**; a truncated collector is not proof that
  an unobserved pointer store cannot alias a CS register.
- Extremely large CFG functions (over 50,000 nodes) and duplicate
  same-PC P-code STORE sites are marked as unresolved for pairwise
  path comparison rather than crashing Analyze.
- Source-limited A-register role hints are downgraded to PATH_UNCERTAIN,
  and reports label all omitted candidate counts. No half-processed
  CFG stage is cached as successful, no Ghidra DB edits are performed.
- Synthetic budget+fail-closed tests, full Ghidra 12.1.4 compile
  and real isolated host acceptance are required.


## 2026-10-29 — GA-02 bounded function-local possible first SIMCR sources

- Stacked draft `feature/hardware-simcr-local-first-paths-20261029`
  is based on immutable PR #75 head `52fbb1ce1f79ff189ff0a28a07d54e8bd6a037ed`.
- For explicitly selected MC68332, each recognized function
  containing a P-code candidate SIMCR write is analyzed using bounded
  Ghidra CFG successors. The result lists *possible first source-PCs
  within that function*, including different literal words in
  alternative branches, unknown values, unknown pointer/call effects,
  CFG cycles, missing edges and work-budget truncation.
- The model **cannot prove a first write since MCU RESET**, runtime
  path feasibility, chip-select configuration or write-once MM latch.
  Generic CPU32 remains outside this MCU-specific display.
- Dedicated pure Java branch/loop/alias/unknown tests and complete
  Ghidra 12.1.4 extension CI; actual on-host Ghidra acceptance
  remains a separate Supervisor gate.

## 2026-10-29 — authoritative GA-18 operational update

- Standing owner authorization covering all standard GhidrAssist
  GA-01..GA-18 tests is **granted, deployed and active on Wyse**.
  Confirmed `codex-supervisor-auto` systemd timer launched the PR #54
  dedicated Codex **test-only** turn at 09:24:15 Europe/Warsaw.
- Private verified real-host Supervisor results exist for
  **PR #53** ([issue #8](https://github.com/bogkom/codex-supervisor/issues/8)),
  **PR #54** ([issue #14](https://github.com/bogkom/codex-supervisor/issues/14),
  PASSED 09:32:49 Warsaw), and **PR #55**
  ([issue #16](https://github.com/bogkom/codex-supervisor/issues/16),
  PASSED 09:51:09 Warsaw). Each result is pinned to its own exact
  historical commit and GitHub Actions artifact.
- Supervisor standing-policy PR #9 remains unmerged to private `main`,
  but its approved functionality was already installed and exercised
  on Wyse using an audited pinned stack based on Supervisor PR #13.
  **Do not call operational activation unconfirmed solely because
  these source PRs remain open.** The auto-reload subfeature has
  not separately been proven by the manual thread reload.
- Later stacked integration PRs #67–#76 still need their **own**
  exact-commit real-Ghidra tests and positive Supervisor reports.
  In particular, a PR #55 success does not verify later source
  combinations or permission for unreviewed production merges.

## GA-06/10 — candidate 2026-11-05: strict physical PDF page claim audit

The read-only profile coverage counter previously accepted any `PDF page`
substring, including invalid, reversed and non-contiguous numbers.
`HardwareProfileAudit.physicalPage` now uses the existing shared
`ManualPdfPageClaim.hasSingleConsistentClaim` to reject misleading
labels. This validates **claim syntax only**, not PDF bytes, editions,
register facts or physical hardware. Needs Java21 and full Ghidra
12.1.4 PUBLIC/Java25 PASS on exact PR SHA. No user firmware or projects.

## GA-08/13 — candidate 2026-11-05: bounded function naming CSV export

The read-only legacy function-role naming CSV now retains at most 5,000
candidate rows and emits an explicit seven-column omitted-row sentinel
(`OMITTED_ROWS`, `INCOMPLETE_EXPORT_NEVER_AUTO_APPLY`). Untrusted cells
remain formula-safe and bounded. No Review/Apply permission or actual
function name is changed; full Ghidra 12.1.4 PUBLIC/Java25 and Java21
regressions require a fresh PASS on the exact candidate SHA.

## GA-02/03/11 — candidate 2026-11-05: separate transitive effect frontier

The generic `HardwareCallEffects` memory STORE/MOVEC inventory now bounds
**scheduled** function PCs (not just examined functions), with an explicit
`TRUNCATED/UNKNOWN` marker after a distinct-call budget overflow. This is
separate from the previously integrated GA-02/03 SIMCR callsite budget.
Deterministic Java21 fixtures cover 12,000 distinct and duplicate edges,
unknown targets, budget validation, and preserve existing shortest-path /
cycle semantics. Full Ghidra 12.1.4 PUBLIC/Java25 CI required on exact PR
SHA. Read-only source evidence, not runtime vector/RESET activation.

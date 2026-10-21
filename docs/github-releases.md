# GhidrAssist — trwałe wydania GitHub Releases

[Lista wydań GhidrAssist](https://github.com/bogkom/GhidrAssist/releases)

Po przejściu automatycznej kompilacji można ręcznie opublikować **trwały ZIP rozszerzenia dla Ghidry 12.1.4** wraz z `SHA256SUMS.txt`. Publikacja jest rozdzielona od codziennych testowych artefaktów GitHub Actions.

## Tworzenie wydania

1. Przejdź do [Actions → Build and publish GhidrAssist Release](https://github.com/bogkom/GhidrAssist/actions/workflows/publish-ghidra-release.yml).
2. Kliknij **Run workflow** i wybierz **Branch: master**.
3. Podaj nowy numer, np. `v0.1.0-beta.1`, oraz domyślny **release_stage: prerelease**.
4. Po zielonym wykonaniu obu zadań, **compile** i **publish**, otwórz [Releases](https://github.com/bogkom/GhidrAssist/releases).
5. Na stronie wydania pobierz **bezpośrednio** plik `ghidra_12.1.4_PUBLIC_<data>_GhidrAssist.zip`. Ten ZIP można wskazać bez rozpakowywania w **Ghidra → File → Install Extensions**.
6. Opcjonalnie sprawdź jego SHA-256 plikiem `SHA256SUMS.txt`.

**Stable** wybieraj dopiero po zweryfikowaniu rozszerzenia w rzeczywistym projekcie Ghidry. `prerelease` jest przeznaczone do testów funkcji na prawdziwym firmware; kompilacja w GitHub Actions nie zastępuje tych testów.

## Cechy i zabezpieczenia

- Nie publikuje nic automatycznie po samym scaleniu PR do `master`. Wymagane jest świadome uruchomienie procedury wydania.
- W pierwszym zadaniu kod jest pobierany, kompilowany z pobranym i zweryfikowanym Ghidrą 12.1.4, a ZIP jest sprawdzany poleceniem `unzip -tq` i otrzymuje SHA-256.
- Drugie zadanie, z uprawnieniem `contents: write`, działa **wyłącznie** po ręcznym `workflow_dispatch` z gałęzi `master`; nie wykonuje się przy sprawdzaniu PR.
- Wydanie dostaje nowy tag `vX.Y.Z` lub `vX.Y.Z-beta.N`; nie można przypadkowo nadpisać istniejącego wydania ani tagu. Automatycznie tworzone są informacje o zmianach.
- ZIP wydania w **GitHub Releases** pozostaje dostępny bez 30-dniowego terminu ważności artefaktów Actions, dopóki wydanie i repozytorium istnieją.
- Wydanie nie zawiera prywatnego pliku firmware ani innych danych z `GhidrAssist-Firmware-Tests`.

## Ochrona gałęzi master

Dla repozytorium polecane są [Settings → Rules → Rulesets](https://github.com/bogkom/GhidrAssist/settings/rules) → **New branch ruleset**, **Target branches: default branch**, status **Active**, z regułami **Restrict deletions** i **Block force pushes**. Nie wymagaj na razie drugiego recenzenta ani nie ustawiaj obowiązkowych status checks bez zapewnienia, że wymagane testy uruchamiają się na *każdym* PR (część workflow ma filtry ścieżek). Zmiana tych ustawień wymaga uprawnienia administratora i działania w panelu GitHub.

## Różnica względem Actions Artifacts

Pakiety z `hardware-extension-build.yml` nadal służą do szybkiego testowania: mają zewnętrzne archiwum GitHub i określony czas przechowywania (obecnie 30 dni). **Releases** to zatwierdzone wydania z właściwym plikiem instalacyjnym i przypiętym numerem wersji.


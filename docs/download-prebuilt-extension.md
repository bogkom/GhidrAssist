# Pobieranie gotowego GhidrAssist dla Ghidry 12.1.4

Gotowe rozszerzenie jest odtąd generowane i udostępniane **automatycznie** po udanej kompilacji w GitHub Actions, bez potrzeby uruchamiania Gradle na komputerze użytkownika.

## Instrukcja pobierania

1. Otwórz [GitHub Actions — Hardware Analysis extension integration build](https://github.com/bogkom/GhidrAssist/actions/workflows/hardware-extension-build.yml).
2. Wybierz najnowszy **udany** przebieg z gałęzi `master` (zielony symbol `✓`). Nie wybieraj przypadkowego buildu z otwartego PR.
3. Na stronie przebiegu, w sekcji **Artifacts**, pobierz `GhidrAssist-Ghidra-12.1.4-<run_id>`.
4. Pobrane archiwum GitHub **rozpakuj**. Zawiera ono:
   - właściwe rozszerzenie `ghidra_12.1.4_PUBLIC_<build-date>_GhidrAssist.zip`;
   - `SHA256SUMS.txt`, z którym można sprawdzić integralność pakietu.
5. W uruchomionej Ghidrze 12.1.4 otwórz **File → Install Extensions**, kliknij dodawanie i wybierz **wewnętrzny ZIP rozszerzenia**. Nie wskazuj zewnętrznego archiwum pobranego z Artifacts.
6. Jeśli wcześniejsza wersja jest zainstalowana, usuń/wyłącz starą wersję zgodnie z mechanizmem zarządzania rozszerzeniami Ghidry, aby uniknąć konfliktu kilku kopii, następnie uruchom Ghidrę ponownie.

**Ważne:** ukończenie kompilacji i jej udostępnienie nie zastępuje uruchomienia oraz przetestowania rozszerzenia na realnym projekcie w Ghidrze. Pakiet z CI jest **testowy**, a nie automatycznie uznany za stabilne wydanie.

## Zasady publikacji

- Kompilacja uruchamia się na odpowiednich zmianach gałęzi `master`, na PR i ręcznie z **Run workflow**.
- Kompilacja używa dokładnie Ghidry **12.1.4** i sprawdzonej sumy SHA-256 instalatora Ghidry.
- Po zbudowaniu sprawdzana jest poprawność archiwum ZIP, generowana suma kontrolna `SHA256SUMS.txt`, a oba pliki wysyłane są do GitHub Actions jako artefakt.
- Artefakt jest przechowywany **30 dni**. GitHub może wymagać zalogowania do pobrania.
- GitHub Releases pozostaje właściwym miejscem na **trwałe, zatwierdzone** wersje programu; CI nie publikuje automatycznie wersji stabilnych.
- Żaden prywatny firmware ECU ani jego zawartość nie są dołączane do publicznego pakietu.


# PythonSecureCrypt
🛡️ Ultra Zabezpečená Šifra (Třívrstvá AES-256 GCM)
Vítejte v projektu Ultra Zabezpečená Šifra! Tento nástroj představuje pokročilou implementaci šifrování textových zpráv v Pythonu. Využívá třívrstvou šifru AES-256 v režimu GCM (Galois/Counter Mode), robustní PBKDF2 pro odvození klíčů z hesla s vysokým počtem iterací, volitelnou kompresi dat a kryptografický hash pro ověření integrity plaintextu.

Je ideální pro ty, kteří chtějí experimentovat s moderními kryptografickými technikami a pochopit principy vícevrstvého šifrování a bezpečného odvozování klíčů.

✨ Klíčové vlastnosti
Třívrstvé šifrování AES-256 GCM: Vaše zprávy jsou zašifrovány třikrát po sobě, každá vrstva s unikátním klíčem odvozeným z hesla.
PBKDF2 pro robustní odvození klíčů: Heslo je pomocí PBKDF2 "roztaženo" s vysokým počtem iterací (až 1.5 milionu), což extrémně ztěžuje útoky hrubou silou. Každá šifrovací vrstva má svůj unikátní klíč, odvozený z master klíče.
Kryptografický hash (SHA512) pro ověření integrity: Před šifrováním je z původní zprávy vypočítán hash, který je zašifrován spolu se zprávou. Při dešifrování se ověří, zda nebyla zpráva poškozena nebo změněna.
Volitelná komprese (zlib): Data jsou před šifrováním komprimována, což může zamaskovat vzory v plaintextu a zmenšit velikost zašifrované zprávy.
Autentizovaný režim GCM: Zajišťuje jak důvěrnost (zašifrování), tak integritu a autenticitu (ověření, že data nebyla změněna) šifrovaných dat.
Jednoduché interaktivní menu: Snadné použití pro šifrování a dešifrování přímo z příkazového řádku.
🚀 Jak zprovoznit a používat
📦 Požadavky
Python 3.x
pycryptodome knihovna: Tato knihovna poskytuje robustní kryptografické algoritmy.
⚙️ Instalace
Naklonujte (clone) repozitář:

Bash

git clone https://github.com/VASE_UZIVATELSKE_JMENO/NAZEV_REPOZITARE.git
cd NAZEV_REPOZITARE
(Nezapomeňte nahradit VASE_UZIVATELSKE_JMENO a NAZEV_REPOZITARE skutečnými údaji.)

Nainstalujte potřebné závislosti:

Bash

pip install pycryptodome
🏃 Jak používat
Spusťte program:

Bash

python cipher_app.py
Interaktivní menu:
Po spuštění se vám zobrazí hlavní menu:

========================================
  ULTRA ZABEZPEČENÁ ŠIFRA (TŘÍVRSTVÁ AES)
========================================
1. Šifrovat zprávu (Koder)
2. Dešifrovat zprávu (Dekoder)
3. Ukončit program
========================================
Zadejte volbu (1, 2 nebo 3):
Šifrování zprávy:

Zvolte 1.
Zadejte zprávu, kterou chcete zašifrovat.
Zadejte silné a unikátní heslo. Čím silnější heslo, tím bezpečnější vaše data!
Program vypíše zašifrovanou zprávu ve formátu Base64. Tuto zprávu (a samozřejmě heslo) si pečlivě uschovejte.
Zadejte volbu (1, 2 nebo 3): 1

--- ŠIFROVÁNÍ ZPRÁVY (TŘÍVRSTVÉ S EXTRA HESLEM) ---
Zadejte zprávu k zašifrování: Ahoj, toto je tajna zprava!
Zadejte EXTRÉMNĚ SILNÉ HESLO pro šifrování: MojeSuperTajneHeslo123!

✅ Zpráva úspěšně zašifrována ve třech vrstvách s kompresí a ověřením integrity!
--------------------------------------------------
Zašifrovaná zpráva (Base64 formát):
[ZDE BUDE DLOUHÝ BASE64 ŘETĚZEC]
--------------------------------------------------
Dešifrování zprávy:

Zvolte 2.
Zadejte celou zašifrovanou zprávu (dlouhý Base64 řetězec), kterou jste získali při šifrování. Buďte opatrní a vložte POUZE zašifrovaný řetězec, bez dalšího textu!
Zadejte přesně to heslo, které jste použil(a) pro zašifrování. Pokud se heslo liší byť jen o písmeno, dešifrování selže a program vás upozorní na chybu integrity.
Zadejte volbu (1, 2 nebo 3): 2

--- DEŠIFROVÁNÍ ZPRÁVY (TŘÍVRSTVÉ S EXTRA HESLEM) ---
Zadejte zašifrovanou zprávu (Base64 formát): [VLOŽTE ZDE DLOUHÝ BASE64 ŘETĚZEC]
Zadejte HESLO pro dešifrování (Musí být stejné, jako při šifrování!): MojeSuperTajneHeslo123!

✅ Zpráva úspěšně dešifrována!
--------------------------------------------------
Dešifrovaná zpráva:
Ahoj, toto je tajna zprava!
--------------------------------------------------
Ukončení programu:

Zvolte 3.
⚠️ Důležité bezpečnostní upozornění
Tento projekt je navržen pro demonstraci pokročilých kryptografických principů a pro vzdělávací účely. Přestože využívá silné a moderní kryptografické algoritmy (AES-256 GCM, PBKDF2), není určen pro použití v kritických produkčních systémech, kde byste měli spíše využít etablované a auditované kryptografické knihovny a protokoly. Implementace vlastní kryptografie bez hlubokých znalostí a nezávislých auditů je vždy riskantní.

🤝 Přispění
Vylepšování je vždy vítáno! Pokud máte nápady na vylepšení kódu, nové funkce nebo opravy chyb, neváhejte otevírat issues nebo posílat pull requesty.

Nezapomeňte nahrát i soubor cipher_app.py do vašeho repozitáře!

Doufám, že se vám to líbí a že to bude užitečné pro vaše publikum na GitHubu!

jako s formatovanim aby si mohly jednoduše zkopirovat kod



Chápu! Chcete, aby ten README.md byl co nejlépe formátovaný pro GitHub, s jasně oddělenými a snadno kopírovatelnými bloky kódu. To je klíčové pro dobrou dokumentaci.

Upravil jsem předchozí návrh tak, aby měl:

Syntax highlighting pro kód (pomocí ```python nebo ```bash)
Kratší, souhrnnější text, který je snazší na čtení.
Konkrétní příkazy s ukázkami výstupu.
Vylepšená předloha pro váš README.md soubor (s důrazem na kopírování kódu)
Stačí zkopírovat celý následující text a vložit ho do souboru README.md ve vašem GitHub repozitáři.

🛡️ Ultra Zabezpečená Šifra (Třívrstvá AES-256 GCM)
Vítejte v projektu Ultra Zabezpečená Šifra! Tento nástroj je pokročilá Python implementace šifrování textu. Využívá třívrstvé AES-256 GCM šifrování, robustní PBKDF2 pro odvození klíčů, volitelnou kompresi dat a kryptografický hash pro ověření integrity.

Je ideální pro demonstraci vícevrstvého šifrování a bezpečného odvozování klíčů.

✨ Klíčové vlastnosti
Třívrstvé AES-256 GCM: Zprávy jsou šifrovány třikrát po sobě, každá vrstva s unikátním klíčem.
Robustní PBKDF2: Heslo je "roztaženo" s velmi vysokým počtem iterací (až 1.5 milionu) pro extrémní odolnost proti útokům hrubou silou.
Integrita dat: Kryptografický hash (SHA512) ověřuje, že data nebyla poškozena.
Komprese (zlib): Data jsou komprimována pro maskování vzorů a zmenšení velikosti.
Interaktivní menu: Snadné použití v příkazovém řádku.
🚀 Jak zprovoznit a používat
📦 Požadavky
Python 3.x
pycryptodome knihovna
⚙️ Instalace
Naklonujte repozitář:

Bash

git clone https://github.com/VASE_UZIVATELSKE_JMENO/NAZEV_REPOZITARE.git
cd NAZEV_REPOZITARE
(Nahraďte zástupné znaky vašimi údaji.)

Nainstalujte závislosti:

Bash

pip install pycryptodome
🏃 Jak používat
Spusťte program:

Bash

python cipher_app.py
Interaktivní menu:
Zobrazí se vám hlavní menu:

========================================
  ULTRA ZABEZPEČENÁ ŠIFRA (TŘÍVRSTVÁ AES)
========================================
1. Šifrovat zprávu (Koder)
2. Dešifrovat zprávu (Dekoder)
3. Ukončit program
========================================
Zadejte volbu (1, 2 nebo 3):
Šifrování zprávy:

Zvolte 1.
Zadejte zprávu k zašifrování.
Zadejte silné a unikátní heslo.
Bash

Zadejte volbu (1, 2 nebo 3): 1

--- ŠIFROVÁNÍ ZPRÁVY (TŘÍVRSTVÉ S EXTRA HESLEM) ---
Zadejte zprávu k zašifrování: Ahoj, toto je tajna zprava!
Zadejte EXTRÉMNĚ SILNÉ HESLO pro šifrování: MojeSuperTajneHeslo123!

✅ Zpráva úspěšně zašifrována ve třech vrstvách s kompresí a ověřením integrity!
--------------------------------------------------
Zašifrovaná zpráva (Base64 formát):
zFlfhqIcJdl91D6+B9FRWg==.Hb3lLuNr73fpyjqHAE3pow==.fiDLWMVqJTLzufRM1T8aVQ==.[...další komponenty...].yv39+E/LE0FTQ6T21oIN+lwia3pGVyTPYZpHp4fbaE4h7Fm70NghYmmPlFLhy3AMDqm2wZ2BaSKIXISVLmr2I09YYLbaWMXuX4tal8eC9p5IiHagQyWDFDfqDOYwBmGdSBIK5j1d4EqJQNfXt101YQ==
--------------------------------------------------
Zkopírujte celou zašifrovanou zprávu.
Dešifrování zprávy:

Zvolte 2.
Vložte celou zašifrovanou zprávu. Vložte POUZE Base64 řetězec, bez dalšího textu!
Zadejte přesně to heslo, které jste použili pro šifrování.
Bash

Zadejte volbu (1, 2 nebo 3): 2

--- DEŠIFROVÁNÍ ZPRÁVY (TŘÍVRSTVÉ S EXTRA HESLEM) ---
Zadejte zašifrovanou zprávu (Base64 formát): zFlfhqIcJdl91D6+B9FRWg==.Hb3lLuNr73fpyjqHAE3pow==.fiDLWMVqJTLzufRM1T8aVQ==.[...další komponenty...].yv39+E/LE0FTQ6T21oIN+lwia3pGVyTPYZpHp4fbaE4h7Fm70NghYmmPlFLhy3AMDqm2wZ2BaSKIXISVLmr2I09YYLbaWMXuX4tal8eC9p5IiHagQyWDFDfqDOYwBmGdSBIK5j1d4EqJQNfXt101YQ==
Zadejte HESLO pro dešifrování (Musí být stejné, jako při šifrování!): MojeSuperTajneHeslo123!

✅ Zpráva úspěšně dešifrována!
--------------------------------------------------
Dešifrovaná zpráva:
Ahoj, toto je tajna zprava!
--------------------------------------------------
Ukončení programu:

Zvolte 3.

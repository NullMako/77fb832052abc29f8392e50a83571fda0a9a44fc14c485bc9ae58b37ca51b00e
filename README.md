# Практичний реверс-інжиніринг: розбір .NET-завантажувача з MalwareBazaar
Я студент, вивчаю кібербезпеку, реверс-інжиніринг та аналіз шкідливого програмного забезпечення. Це мій перший практичний звіт, де я розбираю реальний зразок малвари, знайдений на MalwareBazaar. Мета цього звіту — дослідити поведінку цієї шкідливої програми, вилучити пейлоади та написати своє YARA-правило.

## Інформація про файл
* **Тип загрози:** Dropper
* **Джерело:** MalwareBazaar
* **Вперше виявлено:** 2026-03-03 12:57:28 UTC
* **Мова:** C# (.NET)
* **Розмір:** 69,202,944 байт
* **SHA-256:** `77fb832052abc29f8392e50a83571fda0a9a44fc14c485bc9ae58b37ca51b00e`
* **Розширення:** `.exe`

---

## Статичний аналіз

Першим етапом мого дослідження став статичний аналіз файлу для визначення його архітектури та наявності пакувальників. Використавши утиліту **Detect It Easy (DiE)**, я побачив, що файл скомпільовано для платформи .NET. Це дозволило мені декомпілювати код програми.


<img width="814" height="347" alt="image" src="https://github.com/user-attachments/assets/f3259bee-ffbe-4eeb-8fb3-1c9ca1d13d02" />



Відкривши файл у декомпіляторі dnSpy, я розпочав аналіз його структури. Дослідження коду показало, що цей виконуваний файл діє як "контейнер" (Dropper). Замість того, щоб містити єдиний шкідливий модуль, він приховував у собі цілий арсенал інших зашифрованих файлів. Логіка виконання дроппера виявилася дуже простою: по черзі розшифрувати ці файли в директорію `%Temp%` та запустити. Зазирнувши в директиву `Resources` (Ресурси), я виявив 35 прихованих файлів. 

<img width="1044" height="679" alt="image" src="https://github.com/user-attachments/assets/92970d18-08c8-48c2-9a57-6014a920ff41" />


<img width="495" height="631" alt="image" src="https://github.com/user-attachments/assets/c359403e-be48-455f-bb57-535b5905a478" />


Назви цих файлів сильно відрізняються одна від одної, що свідчить про те, що автор, швидше за все, використовував пейлоади інших авторів.
---

## Патчинг та аналіз шифрування
Щоб безпечно вилучити корисні навантаження без ризику зараження мого середовища, я застосував метод модифікації проміжного коду (або просто **патчинг**). Я знайшов у dnSpy виклик методу `Process.Start(text)`, який відповідав за запуск файлів у системі. Замість того, щоб дозволити вірусу виконати цю команду, я відредагував IL-інструкції, замінивши цей виклик на інструкції NOP-и. Отриманий в результаті патчингу модифікований файл я запустив в ізольованому середовищі. Програма виконала алгоритм розшифрування і зберегла всі 35 корисних навантажень у директорію `%Temp%`, але завдяки впровадженим інструкціям NOP ланцюг виконання не відбувся.

<img width="603" height="697" alt="image" src="https://github.com/user-attachments/assets/fc1ef84d-0607-460d-b543-8f3aadcb730d" />


Але аналіз шифрування зробити все одно треба. Під час дослідження функції `GetTheResource()` з'ясувалося, що зловмисник використав алгоритм AES. Цікавою деталлю стало те, що замість складного ключа розшифрування програма використовує наперед визначений мютекс. Можна було б написати Python-скрипт для автоматичного розшифрування ресурсу, але все ж метод IL-патчингу виявився значно швидшим та ефективнішим у цьому сценарії.

<img width="699" height="129" alt="image" src="https://github.com/user-attachments/assets/022b35e2-2530-4521-a567-35207a17e133" />

<img width="851" height="315" alt="image" src="https://github.com/user-attachments/assets/c90798c0-871b-46cd-8f7a-b0af383d41c3" />

<img width="431" height="128" alt="image" src="https://github.com/user-attachments/assets/9cb58982-3643-414b-803c-b080db7131c8" />


---

## Класифікація пейлоадів
Нижче наведено таблицю з усіма 35 файлами, які були успішно вилучені з контейнера. Ідентифікація сімейств шкідливого ПЗ здійснювалася на основі аналізу хешів на платформі VirusTotal:

| Назва файлу | SHA-256 Hash | Імовірний тип загрози |
| :--- | :--- | :--- |
| `48qKwkR.exe` | `afdce732a421c7f06ed43ec41cf581c023d598f95f1955693606361c554ac7cb` | `Infostealer (Rhadamanthys)` |
| `Launcher_x64.exe` | `35ad11d50fb5ee28e09644cd322eca6a28af0c5c9b70ab5ebaf53243d841ad7f` | `Infostealer (Lumma / StealC)` |
| `LB3.exe` | `cab0f0cf1c8049ede51ea4660ad59912fc07dc9aa63240e9accb8fab33e67f81` | `Unknown (Not found on VirusTotal)` |
| `New Text Document mod.exe` | `2e2e035ece4accdee838ecaacdc263fa526939597954d18d1320d73c8bf810c2` | `Infostealer (AgentTesla)` |
| `niggaaaaa.exe` | `2a9cd95dea7e44cba7056a7a0f38c002399e9af16d0773462f2dd9bb487da8af` | `Infostealer (RedLine)` |
| `nigganet.exe` | `94762281aa0928ebf28457978ad9644ad41840bf7d906b8a2fa2bac6aa0bae59` | `Ransomware (Zombie / Cosmu)` |
| `oi.exe` | `104062fd5acbaa98b1ff629efd20afd61aff3c9e9860b35f2d93f1775a02c36e` | `Generic Injector (Zusy / Vundo)` |
| `Oxymorphazone.exe` | `6879a24530b740ced1f7ddd0923627d0c2e280b35aed6fef0c517429c6f6dffa` | `MBR Wiper / Locker (KillMBR / Abobus)` |
| `RenT7Wg.exe` | `ac2ab493b001c522defd69992db7173a5d696fd29e56f17b4f606da041a3ac3e` | `Infostealer (Lumma)` |
| `Restter.exe` | `e0a47933864e612cd4a661c85a7dac020c17c2e596a2a8e028eac417afaf633c` | `Backdoor / RAT (DarkComet)` |
| `RobloxOptimizer.exe` | `62dc5b6be5c74b221dc9c63013c503158c1b9fe2ddc09e370e99d6903b8aa3f0` | `RAT / Backdoor (Quasar)` |
| `sdoijsgroeij324.exe` | `a64fa4d609d767200a28c055dff1c89f64ec190755c98e8886015500fc414a95` | `Worm / Backdoor (Ganelp)` |
| `Setup.exe` | `143450a83c0654aedc03f58045fdf0db2bbcb0e5b4d99740341b946055a02edd` | `Infostealer / Injector (LummaC2)` |
| `tuffnigga.exe` | `4a9885c2753e3ec891dd1532f2c92326f6015338c9221f9c82226e3642388ba8` | `File Infector / Virus (Floxif / Pioneer)` |
| `Umbral.exe` | `04e5e9c162954f1e177f3a3eedbd525771a2880ea4d86771ba11fe18271591be` | `Infostealer (Umbral)` |
| `4363463463464363463463463.exe` | `2fcad226b17131da4274e1b9f8f31359bdd325c9568665f08fd1f6c5d06a23ce` | `Downloader / Botnet (Amadey)` |
| `Antieac.exe` | `129c164c216599eaae40bae1525cd3780bd38dde58aa1cadab212d806fc99717` | `Infostealer (Salat / Coins)` |
| `aoilj.exe` | `9a25c23f136788e7e461f0747df9c70cf7d548f914c5c1215c09ef2d0de2ce53` | `File Infector (Neshta)` |
| `aoisjf.exe` | `aebddb510b7881514fa8eb86887de99fdd5f0230f7e610d14b16dd1ec3197ffd` | `Trojan-Proxy / Backdoor (Qukart / Berbew)` |
| `aosidjn.exe` | `80ac56600608b893360ca21c047f3fe1dd74159e5b01d6c22daea030ebe9534f` | `Ransomware / Crypter (STOP/Djvu) / Drops Infostealer (Azorult/PWS)` |
| `aosuifhn.exe` | `ed6671c6b7770876f5ef107994cdf5e6d21859d8e305a6fb25e884763a39cd9b` | `Polymorphic File Infector / Stealer (Expiro)` |
| `aso9iu8j1298joisd.exe` | `eed15b1e905a715eef017655ac9644fc8f93ec45b8fa8aaa0e439dfd349191c2` | `Cryptominer / Downloader (XMRig / Banload)` |
| `bb84d74b202b0223952a5ec3035430b938a99704fada5771231b2051324d5f4f.exe` | `bb84d74b202b0223952a5ec3035430b938a99704fada5771231b2051324d5f4f` | `Dropper / Crypter (Wacatac / Kryptik)` |
| `BLToolsPROV2.9.1.exe` | `6643a502221550352e1f5a223660658090dfe1c4859a70513ee1a4e75de3bf41` | `Dropper / RAT (XWorm / RedLine)` |
| `eb80020f1ec5707f1a0ca62eed70eab962386e5a.exe` | `2632e7e831ba7300b3edeaf0af47d664675c3b1b3a57b64e5aa164919451785c` | `Dropper / Downloader (Blihan / Daws)` |
| `ee81207c5562288802020975235c69f1ac8355b67a4a3f646e9d161af84757a5.exe` | `ee81207c5562288802020975235c69f1ac8355b67a4a3f646e9d161af84757a5` | `Backdoor / MBR Wiper (Farfli)` |
| `funny.exe` | `2e2d788192549396779200e8aa8429d5d7e9c12dc8ca6a8fda3404551e61ac2e` | `Infostealer (Tepfer / GCleaner)` |
| `funny1.exe` | `fa7a6912698001a5cbbf537cfea24a2605085d949a880dd218f148cbb54270c8` | `Infostealer (Azorult / AgentTesla)` |
| `funny67.exe` | `191fdbb6f2177e09907dbd71a0def4e790384dc952b4a0159d5bcb83d56a73fe` | `Cryptominer / Banking Trojan (XMRig / Grandoreiro)` |
| `funny78.exe` | `a31da35308c7267eb55f7848d9486eb6d90379b0fd4fcdedd9a13ecc328fb5cb` | `File Infector / Banking Trojan (Ramnit / Nimnul)` |
| `G4gtDRI.exe` | `3d149026b10d769b8e9e85d27c67eda7f07a2ce1672cccd15837d38f1392d8ba` | `Infostealer (LummaC2 / Stealc)` |
| `iZ8POZ6.exe` | `31b352f4bc32c341a4f3be06be6f6c29312e1acc6fd8bf18bfe2826b57563ec1` | `Infostealer / Injector (DeerStealer)` |
| `j9a8isjfoksdlmgwer.exe` | `0e9f894e52814a8d574454338251503ea521c1662678c9bde8768639dfa30617` | `Email-Worm / Botnet (Gigex / Gink)` |
| `k1t.exe` | `a7606bc44210d8c6134717b18ffb775e7a5e4f5eaa6cdd16e2bb678f89beaea8` | `Backdoor / RAT (XWorm / AsyncRAT)` |
| `kaQ7Taz.exe` | `d3cec3fa344606859b31df55ec4371595a6d847c55e7cfe3a95dcd8158712a8a` | `Infostealer (StealC / Vidar clone)` |

---

## Розробка YARA-правила
Для автоматизації виявлення цієї загрози було розроблено YARA-правило. Оскільки .NET-програми зберігають імена внутрішніх ресурсів та масивів у форматі Unicode у відкритому вигляді, YARA здатна виявляти їх навіть без розпакування самого файлу. Як основний індикатор компрометації було обрано унікальний Mutex `9IdKwusY4I7Azr0FN`, що мінімізує ризик хибних спрацювань. Для додаткової точності я додав ще перевірку на наявність файлів з найбільш специфічними іменами, вбудованих у ресурси.

```yara
rule Roblox_NET_Dropper {
    meta:
        author = "NullMako"
        description = "Detects .NET Dropper carrying 35 payloads"
        date = "2026-03-09"
        hash = "77fb832052abc29f8392e50a83571fda0a9a44fc14c485bc9ae58b37ca51b00e"

    strings:
        $mutex = "9IdKwusY4I7Azr0FN" ascii wide

        $f1 = "RobloxOptimizer.exe" ascii wide
        $f2 = "nigganet.exe" ascii wide
        $f3 = "Oxymorphazone.exe" ascii wide
        $f4 = "sdoijsgroeij324.exe" ascii wide
        $f5 = "aso9iu8j1298joisd.exe" ascii wide
        $f6 = "BLToolsPROV2.9.1.exe" ascii wide
        $f7 = "funny67.exe" ascii wide
        
        $mz = { 4D 5A } // Магічні байти MZ

    condition:
        $mz at 0 and (
            $mutex or 
            3 of ($f*)
        )
}
```
## Висновки
Аналіз даного зразка показав, що він є комплексним .NET-завантажувачем (Dropper), головна функція якого полягає у прихованому доставленні великої кількості інших шкідливих програм. Замість єдиного цільового навантаження, цей виконуваний файл містить у директиві ресурсів 35 незалежних компонентів. Для ускладнення статичного аналізу ці файли зашифровані за алгоритмом AES, де функцію ключа декриптування виконує жорстко заданий у коді системний мютекс.

Після успішного розшифрування у тимчасову директорію, дропер почергово запускає усі приховані файли. Вилучені компоненти являють собою широкий спектр загроз різного типу та архітектури: від інфостілерів і прихованих майнерів до троянів віддаленого доступу. Хаотичні назви вбудованих файлів та їхній різноманітний функціонал вказують на те, що технічна мета контейнера — масово і швидко розгорнути максимально можливу кількість шкідливих інструментів.

# LogSentinel SIEM - Sistem de Analiză Corelată pentru Log-uri SSH și Firewall

**LogSentinel SIEM** este o aplicație interactivă în C++ orientată pe obiecte, destinată monitorizării evenimentelor de securitate, detecției atacurilor de tip **SSH Brute-Force** și **Firewall Port Scanning**, precum și corelării atacurilor *multi-stage* (recunoaștere de rețea urmată de compromiterea autentificării).

---

## Arhitectura și Clasele Implementate (9 Clase)

1. **`LogEntry`**: Descompune, validează (format IPv4 și calendar) și încapsulează o înregistrare din log-ul de autentificare SSH (timestamp în secunde, IP sursă, stare autentificare).
2. **`FirewallEntry`**: Descompune și validează pachetele înregistrate de Firewall (timestamp, IP sursă, port destinație `1..65535`, protocol `TCP`/`UDP`/`ICMP`, decizie `BLOCK`/`ALLOW`) și identifică țintirea serviciilor critice (`21`, `22`, `23`, `445`, `1433`, `3306`, `3389`).
3. **`Alert`**: Reprezintă o alertă de securitate unificată (`SSH-BRUTEFORCE`, `FW-PORTSCAN`, `SIEM-CORRELATION` sau `SOC-ESCALATION`) cu nivel de severitate calculat dinamic (`MEDIUM`, `HIGH`, `CRITICAL`). Implementează **Regula celor 3** (constructor de copiere, `operator=` de atribuire și destructor).
4. **`IpTracker`**: Monitorizează încercările de autentificare SSH pentru un IP într-o fereastră temporală glisantă, resetând contoarele la expirarea timpului și generând alerte la depășirea pragului și a ratei de eșec.
5. **`PortScanTracker`**: Urmărește pachetele blocate de Firewall pentru o adresă IP într-o fereastră de timp, contorizând porturile distincte scanate și numărul de servicii critice vizate.
6. **`LogSource`**: Gestionează ingestia din fluxul de intrare, persistența, filtrarea liniilor malformate și sortarea cronologică a log-urilor SSH.
7. **`FirewallSource`**: Gestionează ingestia, validarea, stocarea și ordonarea cronologică a evenimentelor de Firewall.
8. **`Analyzer`**: Motorul central SIEM care compune sursele de date, gestionează colecțiile de trackere active, rulează algoritmii de detecție și corelează alertele cross-log pentru identificarea atacatorilor multi-stage.
9. **`SiemConsoleApp`**: Interfața interactivă în consolă (CLI) a aplicației, care gestionează meniul de operare, ingestia fluxurilor de date din `std::cin` (`tastatura.txt`), actualizarea politicii de securitate în timp real, investigarea IP-urilor (Threat Intelligence) și arhivarea/escaladarea incidentelor.

---

## Funcționalitățile Aplicației (Meniu Interactiv)

* **`[1]` Ingestie log-uri SSH:** Citește și validează înregistrări de autentificare din fluxul de intrare.
* **`[2]` Ingestie log-uri Firewall:** Citește și validează pachete de rețea (UFW/iptables) din fluxul de intrare.
* **`[3]` Configurare politică SIEM:** Permite modificarea dinamică a pragului Brute-Force, a numărului de porturi pentru Port Scan, a ferestrei de timp (secunde) și a ratei minime de eșec.
* **`[4]` Scanare SIEM completă & Corelare:** Execută detecția pe ambele surse, corelează alertele comune aceluiași IP și afișează raportul detaliat.
* **`[5]` Investigare IP (Threat Intelligence):** Afișează întregul istoric SSH, pachetele de Firewall (marcând porturile critice) și alertele asociate unei adrese IP.
* **`[6]` Arhivare și escaladare incident:** Creează o copie de siguranță (snapshot) a alertei prioritare și o escaladează către nivelul SOC Tier-2.
* **`[0]` Ieșire:** Închide sesiunea și afișează rezumatul final al stării SIEM.

---

### Tema 0

- [x] Nume proiect (poate fi schimbat ulterior)
- [x] Scurtă descriere a temei alese, ce v-ați propus să implementați

## Tema 1

#### Cerințe

- [x] definirea a minim **3-4 clase** folosind compunere cu clasele definite de voi; moștenirile nu se iau în considerare aici
- [x] constructori de inițializare cu parametri pentru fiecare clasă
- [x] pentru o aceeași (singură) clasă: constructor de copiere, `operator=` de copiere, destructor

- [x] `operator<<` pentru **toate** clasele pentru afișare (`std::ostream`) folosind compunere de apeluri cu `operator<<`
- [x] cât mai multe `const` (unde este cazul) și funcții `private`
- [x] implementarea a minim 3 funcții membru publice pentru funcționalități netriviale specifice temei alese, dintre care cel puțin 1-2 funcții mai complexe
  * nu doar citiri/afișări sau adăugat/șters elemente într-un/dintr-un vector
- [x] scenariu de utilizare **cu sens** a claselor definite:
  * crearea de obiecte și apelarea tuturor funcțiilor membru publice în main
  * vor fi adăugate în fișierul `tastatura.txt` DOAR exemple de date de intrare de la tastatură (dacă există); dacă aveți nevoie de date din fișiere, creați alte fișiere separat
- [x] minim 52-60% din codul propriu să fie C++, `.gitattributes` configurat corect
- [ ] tag de `git`: de exemplu `v0.1`
- [x] serviciu de integrare continuă (CI) cu **toate bifele**; exemplu: GitHub Actions
- [ ] code review #1 2 proiecte

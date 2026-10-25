Analizor de Loguri SSH (Brute-Force Detector)

Aplicație C++ orientată pe obiecte care analizează loguri de autentificare SSH (clean_auth.log) și detectează automat tentativele de atac Brute-Force. Un IP este marcat ca atacator dacă acumulează cel puțin 5 autentificări eșuate într-o fereastră de 60 de secunde, cu o rată de eșec de minimum 80%.

Structura claselor:

LogEntry: Stochează o încercare de conectare (IP, timp convertit în secunde, status) și oferă metode pentru compararea cronologică și verificarea ferestrei de timp.

Alert: Reprezintă o alertă generată pentru un IP suspect (implementează Regula celor 3: constructor de copiere, operator= și destructor).

IpTracker: Contorizează încercările totale și eșuate ale unui IP în fereastra activă și verifică dacă s-a atins pragul de atac.

LogSource: Citește logurile din fișier, validează intrările și le sortează cronologic.

Analyzer: Parcurge intrările din LogSource, actualizează evidența fiecărui IP prin IpTracker și generează lista finală de alerte (Alert).

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

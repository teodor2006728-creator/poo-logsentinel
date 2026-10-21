Analizor de Loguri SSH (Brute-Force Detector)

Aplicație C++ orientată pe obiecte care analizează loguri de autentificare SSH (clean_auth.log) și detectează automat tentativele de atac Brute-Force. Un IP este marcat ca atacator dacă acumulează cel puțin 5 autentificări eșuate într-o fereastră de 60 de secunde, cu o rată de eșec de minimum 80%.

Structura claselor:

LogEntry: Stochează o încercare de conectare (IP, timp convertit în secunde, status) și oferă metode pentru compararea cronologică și verificarea ferestrei de timp.

Alert: Reprezintă o alertă generată pentru un IP suspect (implementează Regula celor 3: constructor de copiere, operator= și destructor).

IpTracker: Contorizează încercările totale și eșuate ale unui IP în fereastra activă și verifică dacă s-a atins pragul de atac.

LogSource: Citește logurile din fișier, validează intrările și le sortează cronologic.

Analyzer: Parcurge intrările din LogSource, actualizează evidența fiecărui IP prin IpTracker și generează lista finală de alerte (Alert).

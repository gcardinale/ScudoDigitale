# Regole di codice del progetto
Priorità: questo file > convenzioni generali dell'autore > convenzioni native di C#.

- C# moderno: namespace file-scoped, `nullable enable`, `TreatWarningsAsErrors` attivo, `async` fino in fondo con `CancellationToken` su ogni operazione di rete.
- Intestazione `build/header.txt` su ogni `.cs`, prima di qualunque `using`.
- XML doc su tutti i membri pubblici/protetti, in **italiano**. Identificatori in **inglese** (convenzione .NET), testi mostrati all'utente in **italiano** tramite file di risorse (`.resx`) per poter aggiungere l'inglese.
- Test: `Metodo_QuandoCondizione_DovrebbeRisultato`; niente rete reale (server DNS/HTTP/TLS finti in-process, file di esempio in `tests/**/Fixtures`).
- Ogni controllo: id stabile `AREA-TEMA-NNN` (es. `MAIL-DMARC-001`), mai riutilizzato; il testo di rischio e correzione sta nel catalogo, non nel codice di rilevamento.
- Timeout e concorrenza sempre configurabili; valori prudenti di default (es. 50 connessioni TCP contemporanee, 2 s di timeout).
- Nessun `Process.Start` con input dell'utente non validato; comandi di sistema solo con argomenti in lista.
- Nessun segreto nel codice; la chiave HIBP eventuale si legge da variabile d'ambiente o da archivio protetto dell'OS.

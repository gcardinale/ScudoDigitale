# Contribuire a Scudo Digitale

Grazie! Prima di aprire una pull request:

1. **Intestazione obbligatoria** — ogni file `.cs` inizia con il riquadro di [`build/header.txt`](build/header.txt). La CI fallisce se manca. Non rimuoverlo né modificarlo: è un termine della licenza (AGPL sez. 7(b), vedi [NOTICE](NOTICE)).
2. **Documentazione XML** su tutti i membri pubblici e protetti (`CS1591` è un errore di compilazione).
3. **Test** — copertura minima **90%**. Nome dei test: `Metodo_QuandoCondizione_DovrebbeRisultato`. Niente rete reale nei test: usare i server finti in-process.
4. **Nuovi controlli** — implementano `ICheck`, dichiarano area, prerequisiti e `ScopeRequirement`. Un controllo **attivo** non può mai partire senza `IScopeGuard` (vedi [ADR-004](docs/decisions/ADR-004-perimetro-passivo-attivo.md)).
5. **Mai** codice che tenti login, bruteforce, sfruttamento di vulnerabilità, deauth Wi-Fi o pairing forzato Bluetooth.
6. **Commit** che spiegano il *perché*. Contribuendo accetti che il tuo codice sia distribuito con la stessa licenza (AGPL-3.0-or-later + termini aggiuntivi).

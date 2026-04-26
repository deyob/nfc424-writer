# nfc424-writer

CLI Python per programmare tag **NTAG 424 DNA** con **Secure Dynamic
Messaging (SDM/SUN)** usando un lettore contactless PCSC come
**ACS ACR1552U** (o ACR122U). Pensato per il flusso ShopRFID / Authentia:

1. Il portale esporta un CSV batch con i tag da creare (short_code,
   secret_key AES, url_template con placeholder).
2. Questo tool legge il CSV e programma i tag fisici uno alla volta.
3. Il CSV viene aggiornato inline con UID e stato di ciascun tag.

## Cosa fa esattamente ad ogni tag

Per ogni chip NTAG 424 DNA **vergine** (con tutte le chiavi al factory
default 00...00):

1. Seleziona l'applicazione NDEF (AID `D2760000850101`).
2. Legge l'UID a 7 byte.
3. Scrive il file NDEF (02) con l'URL che contiene due placeholder di zeri
   al posto di `{UID_COUNTER}` e `{CMAC}`.
4. Si autentica con AppKey0 (factory key).
5. Abilita SDM sul file 02 (ChangeFileSettings) configurando gli offset
   dei mirror PICCData + CMAC.
6. Cambia AppKey2 dal default alla `secret_key` del CSV: da ora solo il
   backend (che la conosce) può verificare la firma dei tap.

Dopo la programmazione, a ogni scan il chip sostituisce i placeholder con:
- **PICCData** (16 byte cryptogram AES, rappresentato come 32 hex) che
  contiene UID + contatore tap, cifrato con una chiave interna.
- **SDMMAC** (8 byte CMAC troncato = 16 hex) che firma il contenuto
  dinamico con `secret_key`.

Il backend riceve l'URL `/t/<shortCode>?picc_data=<32hex>&cmac=<16hex>`,
cerca il tag per short_code, decifra PICCData, verifica il CMAC: se
matcha il tag è autentico e non clonato.

## Installazione

Richiesto Python 3.11+.

### macOS

```bash
# PCSC è già integrato (servizio di sistema pcscd). Nessun driver vendor
# richiesto per ACR1552U su macOS Big Sur+.

cd nfc424-writer
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Verifica che il lettore sia visto dal SO
nfc424-writer list-readers
```

Se `list-readers` dice "nessun lettore":
1. Collega il lettore via USB
2. Riavvia pcscd:
   ```bash
   sudo launchctl kickstart -k system/com.apple.ifdreader
   ```
3. Riprova.

### Linux

```bash
sudo apt install pcscd libpcsclite-dev libccid swig
sudo systemctl enable --now pcscd

cd nfc424-writer
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
nfc424-writer list-readers
```

### Windows

```powershell
# Il servizio Smart Card (SCardSvr) deve essere attivo.
# Installa il driver ACR se Windows non lo riconosce automaticamente:
#   https://www.acs.com.hk/en/driver/3/acr1552u-portable-nfc-reader-writer/

cd nfc424-writer
py -m venv .venv
.venv\Scripts\activate
pip install -e .
nfc424-writer list-readers
```

## Uso

### Info tag

Appoggia un tag sul lettore e leggine i dati base:

```bash
nfc424-writer info
```

Output atteso:

```
Lettore: ACS ACR1552U ICC Reader 00 00
Appoggia il tag sul lettore...
UID: 04A3B21E9F6580
ATR: 3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 03 00 00 00 00 68
GetVersion (28 byte): 04010103001A05 ...
```

### Programmare un batch (CSV)

Scarica il CSV dal portale (Tag → Export batch), poi:

```bash
nfc424-writer program tags-batch-2026-04-22.csv
```

Il tool ti chiede di appoggiare il primo tag vergine, lo programma e
aggiorna il CSV aggiungendo le colonne `uid`, `programmed_at`, `status`,
`error`. Poi chiede il secondo, e così via.

Se interrompi (Ctrl+C) e rilanci, salta i tag già marcati `status=ok`.

Flag utili:

```bash
# Salta la conferma interattiva tra un tag e l'altro (utile per produzione)
nfc424-writer program file.csv --yes

# Specifica un lettore se ne hai più di uno
nfc424-writer program file.csv --reader "ACR1552"

# Timeout più lungo (default 60s per presentazione tag)
nfc424-writer program file.csv --timeout 120
```

### Programmare un tag singolo (senza CSV)

```bash
nfc424-writer program-one \
  --short-code ABC123 \
  --key 1aee786822f517dbd0d34f6641740e99 \
  --url "https://shoprfid.it/t/ABC123?picc_data={UID_COUNTER}&cmac={CMAC}" \
  --label "Tag di test"
```

## Struttura progetto

```
src/nfc424_writer/
  cli.py                  # Typer: list-readers, info, program, program-one
  reader.py               # Wrapper PCSC (pyscard)
  ntag424.py              # Comandi ISO 7816 NTAG 424 DNA
  crypto.py               # AES-CBC, AES-CMAC, derivazione chiavi EV2
  sdm.py                  # Costruzione NDEF + FileSettings SDM
  source/
    base.py               # Interfaccia BatchSource
    csv_source.py         # Legge/aggiorna CSV batch
    api_source.py         # TODO fase 2: parla direttamente col backend

tests/
  test_crypto.py          # Vettori NIST CMAC, AES-ECB, CBC roundtrip
  test_sdm.py              # Struttura NDEF + offset mirror
```

## Test senza hardware

```bash
pip install -e ".[dev]"
pytest -v
```

Testano la parte crypto (vettori NIST noti) e la costruzione NDEF/SDM.
La parte di comunicazione col chip richiede hardware → va testata col
lettore davanti.

## Avvertenze importanti

### Chiavi AES

- La `secret_key` nel CSV è **l'AppKey2 in chiaro**: chiunque la legga
  può firmare tap validi per quel tag. **Non committare mai i CSV batch**
  in git (`.gitignore` già esclude `tags-batch-*.csv`).
- Dopo aver programmato un tag, conserva il CSV aggiornato in un
  archivio cifrato (LUKS, VeraCrypt, file protetto in Drive ecc.). Se
  perdi la chiave di un tag, non puoi verificare più le sue scansioni.

### AppKey0 (master)

Di default il tool **non cambia AppKey0**: resta 00...00. Questo vuol
dire che chiunque abbia accesso fisico al tag può riprogrammarlo o
resettarlo. Per blindare completamente i tag, implementa (fase successiva)
il cambio anche di AppKey0 con una chiave master archiviata in un KMS.

### Tag già programmati

Il tool assume tag **vergini**. Se provi a programmare un tag in cui
AppKey0 è già stata cambiata, l'autenticazione fallisce con `6982` o
`91AE`. In quel caso:
- Se conosci AppKey0 del tag: serve estendere il CLI con `--current-app0-key`
- Altrimenti il tag è "fritto" (non puoi più cambiargli file settings o chiavi)

### Lettori testati

| Lettore | OS | Status |
|---|---|---|
| ACR1552U | macOS 14+ | Design target, non ancora testato |
| ACR1552U | Windows 11 | Design target |
| ACR122U | Linux | Compatibile (pcscd + libccid) |

## Roadmap

- [x] Fase 1: CSV source, comandi program/info/list-readers
- [ ] Fase 2: `api_source.py` che crea batch direttamente via API Medusa
  (genera short_code + secret_key sul backend, programma e conferma)
- [ ] Verifica CMAC di risposta dal chip (sicurezza incrementale)
- [ ] Comando `reset` (ripristina tag a factory se conosci le chiavi)
- [ ] Comando `verify` (rileggi un tag e controlla che il URL stampato
  matchi quello atteso nel CSV)
- [ ] GUI desktop (Tkinter o web Flask locale) per non-tecnici in produzione
- [ ] Supporto SDMENC (encrypted file data mirror) per scenari più spinti

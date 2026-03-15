# unp7m

**Estrattore e verificatore di firme digitali italiane (.p7m)**

`unp7m` è uno strumento open-source per estrarre documenti da buste crittografiche `.p7m` (CAdES) e verificare firme digitali italiane, sia CAdES (.p7m) che PAdES (firme embedded in PDF).

Funziona su **macOS** e **Windows**, sia da riga di comando che con doppio clic dal file manager.

---

## Funzionalità

- **Estrazione PDF** da file `.p7m`, anche con firme multiple annidate (es. `file.pdf.p7m.p7m.p7m`)
- **Verifica firme CAdES** (.p7m) con supporto a firme nested a qualsiasi livello
- **Verifica firme PAdES** (firme digitali embedded nei PDF)
- **Validazione catena certificati** contro le CA italiane certificate AgID/eIDAS
- **Informazioni firmatario**: nome, cognome, codice fiscale, organizzazione, email
- **Supporto algoritmi**: RSA (SHA1/256/384/512) e ECDSA
- **Gestione certificati scaduti**: verifica al momento della firma
- **Cross-platform**: macOS e Windows
- **Doppio clic**: associa i file `.p7m` e ottieni il PDF estratto con un clic

---

## Download

Scarica l'ultima versione dalla pagina [Releases](../../releases):

| Piattaforma | File | Note |
|-------------|------|------|
| **macOS** | `unp7m-macos.zip` | Contiene `unp7m.app` |
| **Windows** | `unp7m-windows.zip` | Contiene `unp7m.exe` |

### Installazione rapida

**macOS:**
1. Scarica e decomprimi `unp7m-macos.zip`
2. **Importante — sblocco Gatekeeper**: macOS blocca le app scaricate da internet non firmate. Esegui una volta dal Terminale:
   ```bash
   xattr -cr ~/Downloads/unp7m.app
   ```
   In alternativa: tasto destro su `unp7m.app` → **Apri** → clicca **Apri** nel dialogo di avviso.
3. Sposta `unp7m.app` dove preferisci (es. `/Applicazioni`)
4. Tasto destro su un file `.p7m` → **Apri con** → **Altro...** → seleziona `unp7m.app`
5. Spunta **"Apri sempre con"** per associare tutti i `.p7m`

**Windows:**
1. Scarica e decomprimi `unp7m-windows.zip`
2. **Importante — sblocco SmartScreen**: al primo avvio Windows potrebbe mostrare l'avviso *"Windows ha protetto il PC"*. Clicca **"Ulteriori informazioni"** → **"Esegui comunque"**. Basta farlo una sola volta.
3. Tasto destro su un file `.p7m` → **Apri con** → **Scegli un'altra app** → **Cerca nel PC** → seleziona `unp7m.exe`
4. Spunta **"Usa sempre questa app"** per associare tutti i `.p7m`

### Cosa succede al doppio clic

Nella stessa cartella del file `.p7m` vengono creati:
- Il **documento PDF** estratto (es. `documento.pdf`)
- Un **file di log** con le informazioni sulle firme (es. `documento.pdf.p7m.log`)

---

## Uso da riga di comando

`unp7m` è anche un potente strumento CLI. Quando viene lanciato da terminale, stampa le informazioni sulle firme direttamente su stdout.

### Estrarre un PDF da un file .p7m

```bash
unp7m documento.pdf.p7m
```

Output:
```
Signatures found: 1

  Status:      VALID
  Chain:       Valid
  Signer:      MARIO ROSSI
  Org:         AZIENDA SRL
  Serial No:   TINIT-RSSMRA80A01H501U

Extracted: documento.pdf
```

### Firme annidate

```bash
unp7m documento.pdf.p7m.p7m.p7m
```

Output:
```
Signatures found: 3 (nested)

--- Level 1 ---
  Status:      VALID
  Chain:       Valid
  Signer:      MARIO ROSSI
  Serial No:   TINIT-RSSMRA80A01H501U

--- Level 2 ---
  Status:      VALID
  Chain:       Valid
  Expired:     Yes
  Signer:      LUIGI BIANCHI
  Serial No:   TINIT-BNCLGU75B02F205X

--- Level 3 ---
  Status:      VALID
  Chain:       Valid
  Signer:      ANNA VERDI
  Serial No:   TINIT-VRDNNA90C03L219K

Extracted: documento.pdf
```

### Verificare firme PAdES (PDF)

Lo script `verify_signature.py` supporta anche la verifica di firme digitali embedded nei PDF (standard PAdES):

```bash
python verify_signature.py documento_firmato.pdf
```

### Solo verifica, senza estrarre

```bash
unp7m documento.pdf.p7m --no-extract
```

### Output JSON

```bash
unp7m documento.pdf.p7m --json
```

```json
[
  {
    "level": 1,
    "valid": true,
    "expired": false,
    "chain_valid": true,
    "signer": {
      "full_name": "MARIO ROSSI",
      "serial_number": "TINIT-RSSMRA80A01H501U",
      "organization": "AZIENDA SRL"
    }
  }
]
```

### Estrarre in un percorso specifico

```bash
unp7m documento.pdf.p7m -o /path/output.pdf
```

### Specificare un bundle CA personalizzato

```bash
unp7m documento.pdf.p7m --ca-bundle /path/to/ca-bundle.pem
```

### Tutte le opzioni

```
usage: unp7m [-h] [-o OUTPUT] [--no-extract] [--json] [--ca-bundle CA_BUNDLE] [--log LOG] file

Extract PDF from .p7m files and display signature information.

positional arguments:
  file                  Input .p7m file

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output path for extracted file
  --no-extract          Don't extract, only show signature info
  --json                Output signature info as JSON
  --ca-bundle CA_BUNDLE
                        Path to CA certificate bundle
  --log LOG             Path for log file
```

---

## Architettura

Il progetto è composto da quattro moduli:

### `unp7m.py` — Entry point e CLI

Il punto di ingresso principale. Gestisce:
- **Modalità terminale** (CLI): output su stdout con colori ANSI
- **Modalità GUI** (doppio clic): estrazione PDF + creazione file `.log`
- **Apple Events** (macOS): ricezione file tramite "Apri con" nel Finder
- **Argomenti da riga di comando**: parsing con `argparse`

Rileva automaticamente la modalità di esecuzione tramite `sys.stdout.isatty()`.

### `verify_signature.py` — Motore di verifica

Il cuore del progetto. Implementa:

- **Verifica CAdES**: parsing ASN.1/CMS delle buste `.p7m`, verifica della firma crittografica, estrazione del contenuto incapsulato
- **Verifica CAdES nested**: sbuccia ricorsivamente le firme annidate (es. `.p7m.p7m.p7m`), verificando ogni livello
- **Verifica PAdES**: validazione delle firme digitali embedded nei PDF tramite pyHanko
- **Validazione catena certificati**: risale la catena dal certificato del firmatario fino alla CA root trusted
- **Estrazione info firmatario**: nome, cognome, codice fiscale, organizzazione, email dal certificato X.509

Algoritmi supportati:
- RSA con SHA-1, SHA-256, SHA-384, SHA-512
- ECDSA con SHA-256, SHA-384, SHA-512

### `download_ca_italiane.py` — Aggiornamento CA italiane

Scarica e aggiorna il bundle dei certificati delle CA italiane da:
- URL diretti dei principali provider (ArubaPEC, InfoCert, Namirial, Intesi Group)
- Trust Service List ufficiale AgID/eIDAS (`https://eidas.agid.gov.it/TL/TSL-IT.xml`)

Genera il file `ca-italiane.pem` con tutti i certificati trusted.

### `build.py` — Script di build

Automatizza la creazione dell'eseguibile con PyInstaller per la piattaforma corrente. Gestisce automaticamente le differenze tra macOS e Windows.

---

## Build da sorgente

### Requisiti

- Python 3.10+
- pip

### Setup e build

```bash
# Clona il repository
git clone https://github.com/OWNER/unp7m.git
cd unp7m

# Installa le dipendenze
pip install -r requirements.txt
pip install pyinstaller

# Solo su macOS: installa PyObjC per il supporto "Apri con"
pip install pyobjc-core pyobjc-framework-Cocoa

# Build dell'eseguibile
python build.py
```

L'eseguibile verrà creato in:
- **macOS**: `dist/unp7m.app`
- **Windows**: `dist/unp7m.exe`

### Aggiornare i certificati CA

Per aggiornare il bundle delle CA italiane (il repository include già una versione aggiornata):

```bash
python download_ca_italiane.py
```

---

## Uso come libreria Python

Le funzioni di verifica possono essere usate direttamente in altri progetti:

```python
from pathlib import Path
from verify_signature import verify_cades_all_levels, verify_pades

# Verifica CAdES (.p7m)
results = verify_cades_all_levels(Path("documento.pdf.p7m"))
for r in results:
    print(f"Level {r.level}: {'VALID' if r.is_valid else 'INVALID'}")
    print(f"  Signer: {r.signer.full_name}")
    print(f"  Serial: {r.signer.serial_number}")

# Verifica PAdES (PDF con firma embedded)
result = verify_pades(Path("documento_firmato.pdf"))
print(f"PDF signature: {'VALID' if result.is_valid else 'INVALID'}")
```

---

## Dipendenze

| Libreria | Versione | Scopo |
|----------|----------|-------|
| [asn1crypto](https://github.com/wbond/asn1crypto) | >=1.5.1 | Parsing ASN.1/CMS per verifica CAdES |
| [cryptography](https://github.com/pyca/cryptography) | >=41.0.0 | Operazioni crittografiche (X.509, RSA, ECDSA) |
| [pyhanko](https://github.com/MatthiasValvekens/pyHanko) | >=0.21.0 | Verifica firme PAdES nei PDF |
| [pyhanko-certvalidator](https://github.com/MatthiasValvekens/certvalidator) | >=0.26.0 | Validazione catena certificati |

---

## Formati supportati

### CAdES (.p7m)

Lo standard CAdES (CMS Advanced Electronic Signatures) è il formato più comune per i documenti firmati digitalmente in Italia. Il documento originale viene "imbustato" in un contenitore PKCS#7/CMS che include la firma digitale e il certificato del firmatario.

`unp7m` supporta:
- Firme singole
- Firme multiple annidate (es. documento firmato da più persone in sequenza)
- Estrazione automatica del documento originale da qualsiasi livello di annidamento

### PAdES (PDF)

Lo standard PAdES (PDF Advanced Electronic Signatures) prevede che la firma digitale sia embedded direttamente nel file PDF. Lo script `verify_signature.py` verifica queste firme controllando:
- Validità crittografica della firma
- Catena di certificati
- Copertura dell'intero documento
- Stato di scadenza del certificato

---

## Note

- I certificati CA vengono scaricati dalla Trust Service List italiana (AgID/eIDAS)
- Lo script gestisce automaticamente certificati scaduti, validando al momento della firma
- Per file `.p7m` annidati, il documento originale viene estratto dall'ultimo livello

---

## Licenza

[MIT](LICENSE)

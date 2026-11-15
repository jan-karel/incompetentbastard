# Auditmodulecatalogus

Open `/dashboard/audit-modules` via de navigatie. De catalogus is alleen-lezen
en gebruikt dezelfde toegangscontrole als het dashboard.

Dit is een ontwerp- en testvoorziening. Er is geen koppeling met de
agentopdrachtwachtrij, geen uitvoeringsendpoint en geen BOF-runtime.
De Windows-controles zijn als **gepland** geregistreerd; ze zijn niet uitgevoerd
of geïmplementeerd. Het voorbeeldresultaat bevat uitsluitend fictieve gegevens.

## Interfaces

- `GET /api/audit-modules`: catalogus, versies, platformen, architecturen,
  runtime, vereiste rechten en implementatiestatus.
- `GET /api/audit-modules/<id>/compatibility?platform=windows&architecture=x64&runtime=powershell`:
  vergelijkt opgegeven metadata met het moduleontwerp.
- `GET /api/audit-modules/demo-result/example`: fictief auditresultaat met
  `schema_version`, moduleversie, doel, status, bewijs en aanbeveling.

Platformnamen zijn `windows`, `linux` en `macos`; architecturen zijn `x86`,
`x64` en `arm64`. Een match betekent alleen dat de opgegeven metadata past.
Rechten worden niet geverifieerd en `execution_available` blijft `false`.
Ontbrekende metadata geeft geen match. Onbekende module-ID's geven HTTP 404.

## Uitbreiden

Voeg moduleontwerpen als `AuditModule` toe in `meuk/flask/audit_modules.py`.
Beschrijf alleen configuratiecontroles die geen wachtwoorden, hashes, cookies
of procesgeheugen verzamelen. Markeer niet-geïmplementeerde controles als
`planned`. Houd simulaties herkenbaar met `simulated: true` en gebruik deze
nooit als bewijs van een echte systeemcontrole.

## Testen

```bash
.venv/bin/python -m pytest -q tests/test_audit_modules.py
```

De tests gebruiken een tijdelijke database in het geheugen en herstellen de
omgevingsvariabelen. Ze controleren toegang, ontbrekende/mismatched metadata,
implementatiestatus en dat het voorbeeld geen agentopdrachten aanmaakt.

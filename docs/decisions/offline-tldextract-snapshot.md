# De ce `domains.py` forțează snapshot-ul offline pentru tldextract

**Status:** decis de la scrierea inițială a modulului, documentat acum
(mutat din docstring-ul modulului `src/triage/domains.py`)

## Problema

tldextract, cu setările lui implicite, descarcă lista de sufixe publice de
la publicsuffix.org la prima folosire și o ține într-un cache legat de
calea venv-ului. Adică:

- pe VM merge, pentru că cineva a încălzit cache-ul o dată;
- în CI, pe un venv nou, face un request HTTP la pornire;
- în teste, unde socket-urile sunt blocate, pică cu o eroare care nu
  seamănă deloc cu cauza reală.

Un sistem descris ca offline-first nu are voie să iasă în rețea ca să
afle ce e un TLD.

## Decizie

`suffix_list_urls=()` forțează folosirea instantaneului împachetat în
pachet, deci comportamentul e identic pe orice mașină și la orice
moment:

```python
tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)
```

## Consecință

Instantaneul e fix. Când apar TLD-uri noi, se actualizează tldextract în
`requirements.txt` — deliberat, cu un PR, nu pe tăcute la runtime.
Comportamentul rămâne identic pe VM, în CI, și în producție.

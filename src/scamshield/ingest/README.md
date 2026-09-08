# `ingest/` - Input Ingestion

Responsible for: **Normalizing incoming user input.**

Intended responsibilities (later steps - not yet implemented):

- Accept user input in one of three forms:
  - **Message** (free text) -> pass to `nlp/`
  - **URL** (string) -> pass to `url/`
  - **QR code** (image) -> decode via `qr/`
- Detect which type(s) of input were provided
- Normalize the input into a common internal structure
- Sanitize/normalize text before downstream processing (consistent with the dataset privacy rules)

This is the entry point of the analysis pipeline.

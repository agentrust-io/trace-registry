# Privacy

trace-registry is the public accountability layer for TRACE claim anchors. By design it stores, and makes publicly available, the anchor entries that submitters choose to publish.

What is stored: each entry records TRACE claim anchor metadata (for example a claim identifier, digest, timestamp, and inclusion-proof data). This is transparency data intended to be public and tamper-evident. Do not submit anything you do not intend to be public; submitters decide what to anchor.

What is not collected: trace-registry sets no tracking cookies and does not build personal profiles or collect usage analytics about visitors beyond the ordinary web/server logs needed to operate and secure the service.

Removal: because a transparency log is append-only and tamper-evident, entries are generally not deletable. Lawful removal requests are handled case by case; contact the maintainers via issues.

Questions or corrections: https://github.com/agentrust-io/trace-registry/issues

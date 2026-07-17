# Explorer HTML fragments

`../index.parts` is the document-order contract. `00-shell.html` owns the head,
navigation, and shared shell; the remaining files own page markup, overlays,
runtime placement, and the footer.

Do not serve the source shell by itself. Cargo assembles the embedded document
during the build, `serve.py` assembles it in memory, and deployment tooling
writes a complete `index.html` to its destination.

Fragments and `../app.scripts.html` are concatenated as bytes. Keep opening and closing tags at their
existing responsibility boundaries so assembly does not require a templating
language or alter browser parsing order.

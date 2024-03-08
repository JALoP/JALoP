Valgrind is an extremely useful tool for catching non-obvious programming errors during runtime.

During development, valgrind was used to check for memory leaks and potential access of
freed or invalid memory. Unfortunately, not all libraries play nicely with valgrind, leading
to a number of false positives. Versions of openssl prior to 1.1.0, for instance have to be
rebuilt from source with the "purify" option to silence a number of these. LibDB also appears
to generate a number of spurious but apparently harmless warnings from valgrind.

Spurious warnings cluttering up the valgrind report makes it difficult to identify new
or more severe problems. To this end, the file jald-valgrind-supressions has been added to
the repository.
When running valgrind against jald in particular, providing the option "--suppressions=jald-valgrind-suppressions"
will suppress several categories of known warnings that couldn't easily be resolved with changes to the source.

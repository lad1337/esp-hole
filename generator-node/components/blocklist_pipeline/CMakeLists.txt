# Portable core (parse.c/normalize.c/hash.c/generate.c): zero ESP-IDF
# headers, so these also build standalone with plain cc for the host test
# harness (test/ — which links test/sha256_host.c instead of sha256_psa.c).
# sha256_psa.c is the one device-only file, needed only for the real
# ESP-IDF/RISC-V build.
idf_component_register(SRCS "parse.c" "normalize.c" "hash.c" "generate.c" "sha256_psa.c"
                       INCLUDE_DIRS "include"
                       PRIV_REQUIRES mbedtls)

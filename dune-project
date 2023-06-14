(lang dune 3.7)

(name ohpke)

(generate_opam_files true)

(source
 (github FantomeBeignet/ohpke))

(authors "Tom Béné <himself@fantomebeign.net>")

(maintainers "Tom Béné <himself@fantomebeig.net>")

(license ISC)

(documentation https://url/to/documentation)

(package
 (name ohpke)
 (synopsis "HPKE implementation in OCaml")
 (description "RFC 9180 HPKE implementation in OCaml")
 (depends ocaml dune cstruct mirage-crypto mirage-crypto-pk hkdf)
 (tags
  (cryptography "hybrid encryption" "public key")))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/dune-files.html#dune-project

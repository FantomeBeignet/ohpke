(lang dune 3.7)

(name hpke)

(generate_opam_files true)

(source
 (github FantomeBeignet/ohpke))

(authors "Tom Béné <himself@fantomebeign.net>")

(maintainers "Tom Béné <himself@fantomebeig.net>")

(license ISC)

(documentation https://www.fantomebeig.net/projects/ohpke/docs/)

(package
 (name hpke)
 (synopsis "HPKE implementation in OCaml")
 (description "RFC 9180 HPKE implementation in OCaml")
 (depends ocaml dune cstruct mirage-crypto mirage-crypto-pk hkdf)
 (tags
  (cryptography "hybrid encryption" "public key")))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/dune-files.html#dune-project

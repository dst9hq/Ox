(lang dune 3.25)
(name ons)
(generate_opam_files true)

(source (github dst9hq/ons))

(package
 (name ons)
 (synopsis "Independent Reticulum networking stack in OxCaml")
 (description 
   "ons is an independent OxCaml implementation of the public-domain Reticulum
   networking protocol. The project is in pre-alpha development, with
   wire-level interoprability as its primary goal.")
 (tags (networking reticulum mesh radio oxcaml))
 (depends 
   ocaml
   (ppx_expect :with-test)))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/reference/dune-project/index.html

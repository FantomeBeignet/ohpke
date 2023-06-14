type id = [ `HKDF_SHA256 | `HKDF_SHA384 | `HKDF_SHA512 ]

let ids = [ `HKDF_SHA256; `HKDF_SHA384; `HKDF_SHA512 ]

let id_value (id : id) : Cstruct.uint16 =
  match id with `HKDF_SHA256 -> 1 | `HKDF_SHA384 -> 2 | `HKDF_SHA512 -> 3

module type Kdf_suite_id = sig
  val id : Cstruct.t
end

module type KDF = sig
  val extract : ?salt:Cstruct.t -> Cstruct.t -> Cstruct.t
  val expand : prk:Cstruct.t -> ?info:Cstruct.t -> int -> Cstruct.t

  val labeled_extract :
    ?salt:Cstruct.t -> label:Cstruct.t -> Cstruct.t -> Cstruct.t

  val labeled_expand :
    prk:Cstruct.t -> label:Cstruct.t -> ?info:Cstruct.t -> int -> Cstruct.t
end

module Make (Hash : Mirage_crypto.Hash.S) (Id : Kdf_suite_id) : KDF = struct
  let extract ?salt ikm =
    let module HKDF = Hkdf.Make (Hash) in
    HKDF.extract ?salt ikm

  let expand ~prk ?info l =
    let module HKDF = Hkdf.Make (Hash) in
    HKDF.expand ~prk ?info l

  let labeled_extract ?salt ~label ikm =
    let labeled_ikm =
      Cstruct.concat [ Cstruct.of_string "HPKE-v1"; Id.id; label; ikm ]
    in
    let module HKDF = Hkdf.Make (Hash) in
    HKDF.extract ?salt labeled_ikm

  let labeled_expand ~prk ~label ?info l =
    let labeled_info =
      Cstruct.concat
        [
          Rfc8017.i2osp (Z.of_int l) 2;
          Cstruct.of_string "HPKE-v1";
          Id.id;
          label;
          Option.value info ~default:Cstruct.empty;
        ]
    in
    let module HKDF = Hkdf.Make (Hash) in
    HKDF.expand ~prk ?info:(Some labeled_info) l
end

let hkdf_sha256 suite_id = 
  let (module Hash) = (Mirage_crypto.Hash.module_of `SHA256) in
  let (module Id) = (module struct let id = suite_id end: Kdf_suite_id) in
  (module Make (Hash) (Id): KDF)

let hkdf_sha384 suite_id = 
  let (module Hash) = (Mirage_crypto.Hash.module_of `SHA384) in
  let (module Id) = (module struct let id = suite_id end: Kdf_suite_id) in
  (module Make (Hash) (Id): KDF)

let hkdf_sha512 suite_id = 
  let (module Hash) = (Mirage_crypto.Hash.module_of `SHA512) in
  let (module Id) = (module struct let id = suite_id end: Kdf_suite_id) in
  (module Make (Hash) (Id): KDF)

let module_of = function
  | `HKDF_SHA255 -> hkdf_sha256 
  | `HKDF_SHA384 -> hkdf_sha384
  | `HKDF_SHA512 -> hkdf_sha512

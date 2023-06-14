type id = [ `HKDF_SHA256 | `HKDF_SHA384 | `HKDF_SHA512 ]
(** Algorithm codes *)

(** List of the implemented algorithms *)
let ids = [ `HKDF_SHA256; `HKDF_SHA384; `HKDF_SHA512 ]

(** Get the binary identifier corresponding to the algorithm code *)
let id_value (id : id) : Cstruct.uint16 =
  match id with `HKDF_SHA256 -> 1 | `HKDF_SHA384 -> 2 | `HKDF_SHA512 -> 3

module type Kdf_suite_id = sig
  val id : Cstruct.t
end

(** A Key Derivation Function *)
module type KDF = sig
  val nh : int
  (** Output size of the [extract] function in bytes *)

  val extract : ?salt:Cstruct.t -> Cstruct.t -> Cstruct.t
  (** [extract salt ikm] extracts a pseudorandom key of fixed length [nh] bytes from input keying material [ikm] and an optional byte string [salt]*)

  val expand : prk:Cstruct.t -> ?info:Cstruct.t -> int -> Cstruct.t
  (** [expand prk info l] Expand a pseudorandom key [prk] using optional string [info] into [l] bytes of output keying material*)

  (** The following two functions are defined to facilitate domain separation of KDF calls as well as context binding *)

  val labeled_extract :
    ?salt:Cstruct.t -> label:Cstruct.t -> Cstruct.t -> Cstruct.t

  val labeled_expand :
    prk:Cstruct.t -> label:Cstruct.t -> ?info:Cstruct.t -> int -> Cstruct.t
end

(** Make a KDF with the provided hash, The KDF suite ID is used for the [labeled_extract] and [labeled_expand] functions *)
module Make (Hash : Mirage_crypto.Hash.S) (Id : Kdf_suite_id) : KDF = struct
  let nh = Hash.digest_size / 8

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

(** The HKDF_SHA256 KDF *)
let hkdf_sha256 suite_id =
  let (module Hash) = Mirage_crypto.Hash.module_of `SHA256 in
  let (module Id) =
    (module struct
      let id = suite_id
    end : Kdf_suite_id)
  in
  (module Make (Hash) (Id) : KDF)

(** The HKDF_SHA384 KDF *)
let hkdf_sha384 suite_id =
  let (module Hash) = Mirage_crypto.Hash.module_of `SHA384 in
  let (module Id) =
    (module struct
      let id = suite_id
    end : Kdf_suite_id)
  in
  (module Make (Hash) (Id) : KDF)

(** The HKDF_SHA512 KDF *)
let hkdf_sha512 suite_id =
  let (module Hash) = Mirage_crypto.Hash.module_of `SHA512 in
  let (module Id) =
    (module struct
      let id = suite_id
    end : Kdf_suite_id)
  in
  (module Make (Hash) (Id) : KDF)

(** Return the KDF module corresponding to the giver [id] *)
let module_of = function
  | `HKDF_SHA255 -> hkdf_sha256
  | `HKDF_SHA384 -> hkdf_sha384
  | `HKDF_SHA512 -> hkdf_sha512

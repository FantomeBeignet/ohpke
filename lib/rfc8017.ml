let i2osp x xlen = Mirage_crypto_pk.Z_extra.to_cstruct_be ~size:xlen x
let os2ip x = Mirage_crypto_pk.Z_extra.of_cstruct_be x

let xor a b =
  let open Cstruct in
  if length a <> length b then failwith "unequal length"
  else
    let res = sub_copy a 0 (length a) in
    let xor_byte x y = byte_to_int x lxor byte_to_int y |> byte in
    mapi (fun i c -> xor_byte c (get_char b i)) res

(** A zero-copy view of a Reticulum address.

    {v
    Packet buffer:

    Offset       0  1  2                  17 18 ...
                 +--+--+--------------------+--
                 |Header|   Address          |
                 +--+--+--------------------+--
                         ^
                         offset = 2

    View:
      buffer -> original packet
      offset -> first address byte
    v}

    Creating a view does not copy the address bytes.
    The view descriptor itself requires an allocation.
*)
type t =
  { buffer : bytes
  ; offset : int
  }

let length = 16

(** Verify that the complete address fits inside the
    supplied buffer.

    For a 35-byte packet:

    {v
    offset =  2 -> valid
    offset = 18 -> valid
    offset = 20 -> invalid

    Last valid offset = 35 - 16 = 19
    v} *)
let view buffer ~offset =
  if offset < 0 || offset > Bytes.length buffer - length
  then invalid_arg "Address.view";
  { buffer; offset }
;;

(** Read one address octet.

    The address index is relative to its view, not
    relative to the beginning of the packet.
*)
let get t index =
  if index < 0 || index >= length then invalid_arg "Address.get";
  Bytes.get_uint8 t.buffer (t.offset + index)
;;

(** Compare two 16-byte addresses without copying.

    {v
    A[0] == B[0]
    A[1] == B[1]
       ...
    A[15] == B[15]
    v}

    Addresses are public identifiers. This comparison is just a helper (not
    intended for secret cryptographic material).
*)
let equal a b =
  let rec loop i =
    if i = length
    then true
    else if get a i <> get b i
    then false
    else loop (i + 1)
  in
  loop 0
;;

(** Create an independently owned address buffer.

    Safe copy helper when the packet buffer may be reused while the address
    must remain available.
*)
let copy t = Bytes.sub t.buffer t.offset length

(** Helper func.

    This allocates a new string and is not intended
    for the packet-processing hot path.
*)
let to_hex t =
  let digits = "0123456789abcdef" in
  let out = Bytes.create (length * 2) in
  for i = 0 to length - 1 do
    let byte = get t i in
    Bytes.set out (i * 2) digits.[byte lsr 4];
    Bytes.set out ((i * 2) + 1) digits.[byte land 0x0f]
  done;
  Bytes.to_string out
;;

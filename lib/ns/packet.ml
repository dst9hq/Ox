module Header = struct
  type t = int

  let of_octets ~flags ~hops =
    if flags land lnot 0xff <> 0 || hops land lnot 0xff <> 0
    then invalid_arg "Packet.Header.of_octets";
    (flags lsl 8) lor hops
  ;;

  let[@zero_alloc] flags t = t lsr 8
  let[@zero_alloc] hops t = t land 0xff
  let[@zero_alloc] ifac t = t land 0x8000 <> 0
  let[@zero_alloc] two_addresses t = t land 0x4000 <> 0
  let[@zero_alloc] context_flag t = t land 0x2000 <> 0
  let[@zero_alloc] transport t = t land 0x1000 <> 0
  let[@zero_alloc] destination_type t = (t lsr 10) land 0x03
  let[@zero_alloc] packet_type t = (t lsr 8) land 0x03

  let decode buf ~offset =
    if offset < 0 || offset > Bytes.length buf - 2
    then invalid_arg "Packet.Header.decode";
    let hi = Bytes.get_uint8 buf offset in
    let lo = Bytes.get_uint8 buf (offset + 1) in
    (hi lsl 8) lor lo
  ;;

  let encode buf ~offset t =
    if offset < 0 || offset > Bytes.length buf - 2
    then invalid_arg "Packet.Header.encode";
    Bytes.set_uint8 buf offset (flags t);
    Bytes.set_uint8 buf (offset + 1) (hops t)
  ;;
end

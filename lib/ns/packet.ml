(** Reticulum packet header.

    The header occupies two octets.

    {v
    Bit     15  14  13  12  11 10  9 8    7 ........ 0
            IF  HD  CT  PR   DST    PKT        HOPS

    Field           Bits    Values
    --------------------------------------------------
    IFAC            15      0 open, 1 authenticated
    Header type     14      0 HEADER_1, 1 HEADER_2
    Context flag    13      0 unset, 1 set
    Propagation     12      0 broadcast, 1 transport
    Destination     11:10   00 single, 01 group
                            10 plain,  11 link
    Packet type      9:8    00 data, 01 announce
                            10 link request, 11 proof
    Hop count        7:0    0 to 255

    HEADER_1: two-byte header, one 16-byte address.
    HEADER_2: two-byte header, two 16-byte addresses.

    The context flag is interpreted according to packet
    context. An authenticated packet includes an interface
    access code (IFAC) after the header.

    Example from the Reticulum specification:

    01010000 00000100 = 0x5004

    IFAC          = disabled
    Header type   = HEADER_2
    Context flag  = unset
    Propagation   = TRANSPORT
    Destination   = SINGLE
    Packet type   = DATA
    Hops          = 4

    Wire layout:

    [0x50 0x04]
    [HASH1: 16 bytes]
    [HASH2: 16 bytes]
    [CONTEXT: 1 byte]
    [DATA]
    v} *)

module Header = struct
  (** Packed 16-bit header represented as an immediate integer. *)
  type t = int

  type destination =
    | Single
    | Group
    | Plain
    | Link

  type packet_type =
    | Data
    | Announce
    | Link_request
    | Proof

  type header_type =
    | Header_1
    | Header_2

  type propagation =
    | Broadcast
    | Transport

  (** of_octets constructs a header from two unsigned octets.

      {v
      Flags           00000000 01010000
      flags lsl 8     01010000 00000000
      Hops            00000000 00000100
                      -----------------
      OR              01010000 00000100

      Result = 0x5004
      v}

      Reject values outside the unsigned 8-bit range. *)
  let of_octets ~flags ~hops =
    if flags land lnot 0xff <> 0 || hops land lnot 0xff <> 0
    then invalid_arg "Packet.Header.of_octets";
    (flags lsl 8) lor hops
  ;;

  (** make onstructs the flags octet from typed fields.

    {v
    IFAC          0 << 7 = 00000000
    HEADER_2      1 << 6 = 01000000
    CONTEXT       0 << 5 = 00000000
    TRANSPORT     1 << 4 = 00010000
    SINGLE       00 << 2 = 00000000
    DATA                 = 00000000
                          --------
    Flags                 01010000

    Flags << 8            01010000 00000000
    Hops                  00000000 00000100
                          -----------------
    Header                01010000 00000100

    Result = 0x5004
    v} *)
  let make
    ~ifac
    ~header_type
    ~context_flag
    ~propagation_type
    ~destination_type
    ~packet_type
    ~hops
    =
    let ifac_bit = if ifac then 1 else 0 in
    let header_bit =
      match header_type with
      | Header_1 -> 0
      | Header_2 -> 1
    in
    let contex_bit = if context_flag then 1 else 0 in
    let propagation_bit =
      match propagation_type with
      | Broadcast -> 0
      | Transport -> 1
    in
    let destination_bit =
      match destination_type with
      | Single -> 0
      | Group -> 1
      | Plain -> 2
      | Link -> 3
    in
    let packed_bits =
      match packet_type with
      | Data -> 0
      | Announce -> 1
      | Link_request -> 2
      | Proof -> 3
    in
    let flags =
      (ifac_bit lsl 7)
      lor (header_bit lsl 6)
      lor (contex_bit lsl 5)
      lor (propagation_bit lsl 4)
      lor (destination_bit lsl 2)
      lor packed_bits
    in
    of_octets ~flags ~hops
  ;;

  (** flag extracts the upper eight bits.

      {v
      Original        01010000 00000100
      Shift right 8   00000000 01010000

      Result = 0x50
      v} *)
  let[@zero_alloc] flags t = t lsr 8

  (** hops extracts the lower eight bits.

      {v
      Original        01010000 00000100
      Mask            00000000 11111111
                      -----------------
      AND             00000000 00000100

      Result = 4
      v} *)
  let[@zero_alloc] hops t = t land 0xff

  (** Test bit 15: Interface Access Code.

      {v
      0x5004          01010000 00000100
      0x8000          10000000 00000000
                      -----------------
      AND             00000000 00000000

      Result = false (open interface)
      v} *)
  let[@zero_alloc] ifac t = t land 0x8000 <> 0

  (** Test bit 14: Header type.

      {v
      0x5004          01010000 00000100
      0x4000          01000000 00000000
                      -----------------
      AND             01000000 00000000

      Result = true (HEADER_2, two addresses)
      v} *)
  let[@zero_alloc] header_type t =
    if t land 0x4000 = 0 then Header_1 else Header_2
  ;;

  (** Test bit 13: Context flag.

      {v
      0x5004          01010000 00000100
      0x2000          00100000 00000000
                      -----------------
      AND             00000000 00000000

      Result = false (unset)
      v} *)
  let[@zero_alloc] context_flag t = t land 0x2000 <> 0

  (** Test bit 12: Propagation type.

      {v
      0x5004          01010000 00000100
      0x1000          00010000 00000000
                      -----------------
      AND             00010000 00000000

      Result = true (TRANSPORT)
      v} *)
  let[@zero_alloc] propagation_type t =
    if t land 0x1000 = 0 then Broadcast else Transport
  ;;

  (** extract_two_bits is a helper func.

    Shift right by [by] positions, then retain bits 1:0.

    field(t, by) = (t >> by) & 0x03
*)
  let[@zero_alloc] extract_two_bits ~by t = (t lsr by) land 0x03

  (** destination_type extracts bits 11 and 10: Destination type.

      Shift the field to positions 1:0, then mask.

      {v
      Original        01010000 00000100
      Shift right 10  00000000 00010100
      Mask            00000000 00000011
                      -----------------
      AND             00000000 00000000

      Result = 0 (SINGLE)

      00 SINGLE
      01 GROUP
      10 PLAIN
      11 LINK
      v} *)
  let[@zero_alloc] destination_type t =
    match extract_two_bits ~by:10 t with
    | 0 -> Single
    | 1 -> Group
    | 2 -> Plain
    | _ -> Link
  ;;

  (** packet_type extracts bits 9 and 8: Packet type.

      Shift the field to positions 1:0, then mask.

      {v
      Original        01010000 00000100
      Shift right 8   00000000 01010000
      Mask            00000000 00000011
                      -----------------
      AND             00000000 00000000

      Result = 0 (DATA)

      00 DATA
      01 ANNOUNCE
      10 LINK REQUEST
      11 PROOF
      v} *)
  let[@zero_alloc] packet_type t =
    match extract_two_bits ~by:8 t with
    | 0 -> Data
    | 1 -> Announce
    | 2 -> Link_request
    | _ -> Proof
  ;;

  (** Decode two octets in network byte order.

      {v
      buf[offset]     = 0x50
      buf[offset + 1] = 0x04

      hi lsl 8        = 0x5000
      lo              = 0x0004
      OR              = 0x5004
      v}

      Raises [Invalid_argument] for an invalid offset. *)
  let decode buf ~offset =
    if offset < 0 || offset > Bytes.length buf - 2
    then invalid_arg "Packet.Header.decode";
    let hi = Bytes.get_uint8 buf offset in
    let lo = Bytes.get_uint8 buf (offset + 1) in
    (hi lsl 8) lor lo
  ;;

  (** Encode the header into two octets.

      {v
      Header          = 0x5004
      Upper octet     = 0x50
      Lower octet     = 0x04

      buf[offset]     <- 0x50
      buf[offset + 1] <- 0x04
      v}

      Raises [Invalid_argument] for an invalid offset. *)
  let encode buf ~offset t =
    if offset < 0 || offset > Bytes.length buf - 2
    then invalid_arg "Packet.Header.encode";
    Bytes.set_uint8 buf offset (flags t);
    Bytes.set_uint8 buf (offset + 1) (hops t)
  ;;
end

module Layout = struct
  type t =
    { header : Header.t
    ; transport : Address.t option
    ; destination : Address.t
    ; context : int
    ; data_offset : int
    ; data_length : int
    }

  type error =
    | Truncated_header
    | Truncated_fields
    | Ifac_requires_verification
    | Payload_too_large

  let mtu = 500
  let header_length = 2
  let context_length = 1
  let header t = t.header
  let transport t = t.transport
  let destination t = t.destination
  let context t = t.context
  let data_offset t = t.data_offset
  let data_length t = t.data_length

  (** Decode the structural layout of a Reticulum packet.

      The destination offset depends on the header type:

      {v
      HEADER_1
        destination = 2
        data = 2 + 16 + 1 = 19

      HEADER_2
        destination = 2 + 16 = 18
        data = 2 + 16 + 16 + 1 = 35

      Maximum packet size = 500 bytes.

      Maximum data length:
        HEADER_1 = 500 - 19 = 481
        HEADER_2 = 500 - 35 = 465
      v}

      Address views borrow the original buffer.
      IFAC verification is not implemented here.
  *)
  let decode buf =
    let size = Bytes.length buf in
    if size < header_length
    then Error Truncated_header
    else (
      let header = Header.decode buf ~offset:0 in
      if Header.ifac header
      then Error Ifac_requires_verification
      else (
        let header_type = Header.header_type header in
        let transport_length =
          match header_type with
          | Header.Header_1 -> 0
          | Header.Header_2 -> Address.length
        in
        let destination_offset = header_length + transport_length in
        let data_offset =
          destination_offset + Address.length + context_length
        in
        if size < data_offset
        then Error Truncated_fields
        else (
          let transport =
            match header_type with
            | Header.Header_1 -> None
            | Header.Header_2 ->
              Some (Address.view buf ~offset:header_length)
          in
          Ok
            { header
            ; transport
            ; destination = Address.view buf ~offset:destination_offset
            ; context = Bytes.get_uint8 buf (data_offset - context_length)
            ; data_offset
            ; data_length = size - data_offset
            })))
  ;;
end

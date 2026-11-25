(** {1 Reticulum Wire Format}

    A Reticulum packet consists of four fields:

    {v
    [HEADER] [ADDRESSES] [CONTEXT] [DATA]
     2 bytes  16/32 bytes  1 byte  0-465 bytes
    v}

    {2 Header}

    The HEADER field occupies two bytes.

    - Byte 1 contains the IFAC flag, header type, context
      flag, propagation type, destination type, and packet type.
    - Byte 2 contains the hop count.

    {2 Interface Access Code}

    If the IFAC flag is set, an Interface Access Code is
    included after the header.

    Its length varies from 1 to 64 bytes, depending on the
    physical interface and its configuration.

    {2 Addresses}

    The ADDRESSES field contains one or two 16-byte addresses.

    - HEADER_1 specifies one address.
    - HEADER_2 specifies two addresses.
    - Addresses are SHA-256 hashes truncated to 16 bytes.

    {2 Context}

    The CONTEXT field occupies one byte and determines the
    context in which Reticulum interprets the packet.

    {2 Data}

    The DATA field contains between 0 and 465 bytes of
    payload data.

    Reference: https://reticulum.network/manual/
*)

module Header : sig
  type t

  (** Reticulum destination types.

      {v
      00 SINGLE
      01 GROUP
      10 PLAIN
      11 LINK
      v} *)

  type destination =
    | Single
    | Group
    | Plain
    | Link

  (** Reticulum packet types.
   
      {v
      Bits  Type
      00    DATA
      01    ANNOUNCE
      10    LINKREQUEST
      11    PROOF
      v} *)
  type packet_type =
    | Data
    | Announce
    | Link_request
    | Proof

  (** Reticulum header types.
    
     {v
      0 HEADER_1: one 16-byte addr 
      1 HEADER_2: two 16-byte addr
      v}
   *)
  type header_type =
    | Header_1
    | Header_2

  (** Reticulum propagation types. 


    {v
    0 BROADCAST
    1 TRANSPORT
    v}
   *)
  type propagation =
    | Broadcast
    | Transport

  (**
      The mathematics:
       F = (I << 7) | (H << 6) | (C << 5) |
           (R << 4) | (D << 2) | P
      reduces to:
      
      Header = (F << 8) | Hops

      Where:
        F    = Flags octet
        I    = IFAC flag
        H    = Header type
        C    = Context flag
        R    = Propagation type
        D    = Destination type
        P    = Packet type

        <<   = Bitwise left shift
        |    = Bitwise OR
   *)

  (** Construct a header from typed protocol fields.

      Each field is encoded at its specified bit offset.

      {v
      IFAC         bit 7
      Header       bit 6
      Context      bit 5
      Propagation  bit 4
      Destination  bits 3:2
      Packet       bits 1:0
      Hops         second octet
      v}

      @raise Invalid_argument if hops is outside 0..255. *)
  val make
    :  ifac:bool
    -> header_type:header_type
    -> context_flag:bool
    -> propagation_type:propagation
    -> destination_type:destination
    -> packet_type:packet_type
    -> hops:int
    -> t

  val of_octets : flags:int -> hops:int -> t
  val decode : bytes -> offset:int -> t
  val encode : bytes -> offset:int -> t -> unit
  val flags : t -> int
  val hops : t -> int
  val ifac : t -> bool
  val context_flag : t -> bool
  val header_type : t -> header_type
  val propagation_type : t -> propagation
  val destination_type : t -> destination
  val packet_type : t -> packet_type
end

(** {1 Packet Layout}

    Decodes the structural fields of a Reticulum packet.

    No address or payload bytes are copied.

    {v
    HEADER_1:
      [HEADER:2] [DEST:16] [CTX:1] [DATA:N]

    HEADER_2:
      [HEADER:2] [TRANSPORT:16] [DEST:16]
      [CTX:1] [DATA:N]
    v}

    IFAC-protected packets require authentication
    before structural decoding.
*)
module Layout : sig
  type t

  type error =
    | Truncated_header
    | Truncated_fields
    | Ifac_requires_verification
    | Payload_too_large

  val decode : bytes -> (t, error) result
  val header : t -> Header.t
  val transport : t -> Address.t option
  val destination : t -> Address.t
  val context : t -> int
  val data_offset : t -> int
  val data_length : t -> int
end

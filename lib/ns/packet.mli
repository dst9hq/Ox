(* == Reticulum Wire Format ======

   A Reticulum packet is composed of the following fields:

   [HEADER 2 bytes] [ADDRESSES 16/32 bytes] [CONTEXT 1 byte]
   [DATA 0-465 bytes]

   - The HEADER field is 2 bytes long.
     - Byte 1: [IFAC Flag], [Header Type], [Context Flag],
       [Propagation Type], [Destination Type] and [Packet Type]
     - Byte 2: Number of hops

   - Interface Access Code field if the IFAC flag was set.
     - The length of the Interface Access Code can vary from 1 to 64 bytes
       according to physical interface capabilities and configuration.

   - The ADDRESSES field contains either 1 or 2 addresses.
     - Each address is 16 bytes long.
     - The Header Type flag in the HEADER field determines whether the
       ADDRESSES field contains 1 or 2 addresses.
     - Addresses are SHA-256 hashes truncated to 16 bytes.

   - The CONTEXT field is 1 byte.
     - It is used by Reticulum to determine packet context.

   - The DATA field is between 0 and 465 bytes.
     - It contains the packets data payload.
*)

module Header : sig
  type t

  val of_octets : flags:int -> hops:int -> t
  val decode : bytes -> offset:int -> t
  val encode : bytes -> offset:int -> t -> unit
  val flags : t -> int
  val hops : t -> int
  val ifac : t -> bool
  val two_addresses : t -> bool
  val context_flag : t -> bool
  val transport : t -> bool
  val destination_type : t -> int
  val packet_type : t -> int
end

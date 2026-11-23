(** {1 Reticulum Addresses}

    Reticulum addresses are 128-bit hashes.

    The wire representation contains exactly 16 bytes,
    derived by truncating a SHA-256 hash.

    {v
    HEADER_1
    [HEADER: 2] [DESTINATION: 16] [CONTEXT: 1]

    HEADER_2
    [HEADER: 2] [TRANSPORT: 16] [DESTINATION: 16]
    [CONTEXT: 1]
    v}

    This module represents an address as a view into an
    existing byte buffer. No address bytes are copied
    when creating a view.
*)

(** A borrowed view of a 16-byte address.

    The backing buffer remains mutable by its owner.
    Its contents must remain stable while the view is
    being used. *)
type t

(** Number of bytes in a Reticulum address. *)
val length : int

(** Create a view at the specified byte offset.

    @raise Invalid_argument if fewer than 16 bytes remain. *)
val view : bytes -> offset:int -> t

(** Create a view at the specified byte offset.

    @raise Invalid_argument if fewer than 16 bytes remain. *)
val get : t -> int -> int

(** Compare the contents of two address views. *)
val equal : t -> t -> bool

(** Copy the address into an independent 16-byte buffer. *)
val copy : t -> bytes

(** Return the address as 32 lowercase hexadecimal digits. *)
val to_hex : t -> string

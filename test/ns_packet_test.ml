module H = Ox.Ns.Packet.Header
module P = Printf

let string_of_header_type = function
  | H.Header_1 -> "HEADER_1"
  | H.Header_2 -> "HEADER_2"
;;

let string_of_propagation = function
  | H.Broadcast -> "BROADCAST"
  | H.Transport -> "TRANSPORT"
;;

let%expect_test "Reticulum header" =
  let input = Bytes.of_string "\x50\x04" in
  let h = H.decode input ~offset:0 in
  P.printf "flags: %02x\n" (H.flags h);
  P.printf "hops: %d\n" (H.hops h);
  P.printf "ifac: %b\n" (H.ifac h);
  P.printf "header: %s\n" (string_of_header_type (H.header_type h));
  P.printf "propagation: %s\n" (string_of_propagation (H.propagation_type h));
  P.printf "context: %b\n" (H.context_flag h);
  let destination =
    match H.destination_type h with
    | Single -> "SINGLE"
    | Group -> "GROUP"
    | Plain -> "PLAIN"
    | Link -> "LINK"
  in
  P.printf "destination: %s\n" destination;
  let packet =
    match H.packet_type h with
    | H.Data -> "DATA"
    | H.Announce -> "ANNOUNCE"
    | H.Link_request -> "LINKREQUEST"
    | H.Proof -> "PROOF"
  in
  P.printf "packet: %s\n" packet;
  [%expect
    {|
    flags: 50
    hops: 4
    ifac: false
    header: HEADER_2
    propagation: TRANSPORT
    context: false
    destination: SINGLE
    packet: DATA
    |}]
;;

let%expect_test "all 65536 headers roundtrip" =
  let buf = Bytes.create 2 in
  for flags = 0 to 255 do
    for hops = 0 to 255 do
      let expected = H.of_octets ~flags ~hops in
      H.encode buf ~offset:0 expected;
      let actual = H.decode buf ~offset:0 in
      if H.flags actual <> flags || H.hops actual <> hops
      then failwith (P.sprintf "header mismatch: %02x %02x" flags hops)
    done
  done;
  print_endline "65536 headers verified";
  [%expect {| 65536 headers verified |}]
;;

let rejected f =
  try
    f ();
    print_endline "accepted"
  with
  | Invalid_argument _ -> print_endline "rejected"
;;

let%expect_test "invalid headers" =
  rejected (fun () -> ignore (H.of_octets ~flags:256 ~hops:0));
  rejected (fun () -> ignore (H.of_octets ~flags:0 ~hops:(-1)));
  rejected (fun () -> ignore (H.decode Bytes.empty ~offset:0));
  rejected (fun () ->
    H.encode (Bytes.create 2) ~offset:2 (H.of_octets ~flags:0 ~hops:0));
  [%expect {|
    rejected
    rejected
    rejected
    rejected
  |}]
;;

let%expect_test "destination types" =
  let examples = [ 0x00; 0x04; 0x08; 0x0c ] in
  List.iter
    (fun flags ->
      let h = H.of_octets ~flags ~hops:0 in
      let destination =
        match H.destination_type h with
        | H.Single -> "SINGLE"
        | H.Group -> "GROUP"
        | H.Plain -> "PLAIN"
        | H.Link -> "LINK"
      in
      P.printf "0x%02x: %s\n" flags destination)
    examples;
  [%expect
    {|
      0x00: SINGLE
      0x04: GROUP
      0x08: PLAIN
      0x0c: LINK
    |}]
;;

let%expect_test "destination independence" =
  let expected = [| H.Single; H.Group; H.Plain; H.Link |] in
  for flags = 0 to 255 do
    for hops = 0 to 255 do
      let h = H.of_octets ~flags ~hops in
      let index = (flags land 0x0c) lsr 2 in
      if H.destination_type h <> expected.(index)
      then failwith (P.sprintf "destination mismatch: %02x %02x" flags hops)
    done
  done;
  print_endline "65536 destination fields verified";
  [%expect {| 65536 destination fields verified |}]
;;

let%expect_test "packet type independence" =
  let expected = [| H.Data; H.Announce; H.Link_request; H.Proof |] in
  for flags = 0 to 255 do
    for hops = 0 to 255 do
      let h = H.of_octets ~flags ~hops in
      let index = flags land 0x03 in
      if H.packet_type h <> expected.(index)
      then failwith (P.sprintf "packet type mismatch: %02x %02x" flags hops)
    done
  done;
  print_endline "65536 packet types verified";
  [%expect {| 65536 packet types verified |}]
;;

let%expect_test "header and propagation types" =
  let examples = [ "\x50\x04"; "\x00\x07" ] in
  List.iter
    (fun input ->
      let h = H.decode (Bytes.of_string input) ~offset:0 in
      P.printf
        "%02x: %s %s\n"
        (H.flags h)
        (string_of_header_type (H.header_type h))
        (string_of_propagation (H.propagation_type h)))
    examples;
  [%expect {|
    50: HEADER_2 TRANSPORT
    00: HEADER_1 BROADCAST
    |}]
;;

let%expect_test "header and propagation independence" =
  for flags = 0 to 255 do
    for hops = 0 to 255 do
      let h = H.of_octets ~flags ~hops in
      let header = if flags land 0x40 = 0 then H.Header_1 else H.Header_2 in
      let propagation =
        if flags land 0x10 = 0 then H.Broadcast else H.Transport
      in
      if H.header_type h <> header || H.propagation_type h <> propagation
      then failwith (P.sprintf "header mismatch: %02x %02x" flags hops)
    done
  done;
  print_endline "65536 header combinations verified";
  [%expect {| 65536 header combinations verified |}]
;;

let%expect_test "typed header construction" =
  let h =
    H.make
      ~ifac:false
      ~header_type:H.Header_2
      ~context_flag:false
      ~propagation_type:H.Transport
      ~destination_type:H.Single
      ~packet_type:H.Data
      ~hops:4
  in
  P.printf "%04x\n" ((H.flags h lsl 8) lor H.hops h);
  [%expect {| 5004 |}]
;;

(** Exhaustively reconstruct every possible header.

   make(fields(h)) = h
 *)
let%expect_test "typed construction roundtrip" =
  for flags = 0 to 255 do
    for hops = 0 to 255 do
      let original = H.of_octets ~flags ~hops in
      let reconstructed =
        H.make
          ~ifac:(H.ifac original)
          ~header_type:(H.header_type original)
          ~context_flag:(H.context_flag original)
          ~propagation_type:(H.propagation_type original)
          ~destination_type:(H.destination_type original)
          ~packet_type:(H.packet_type original)
          ~hops
      in
      if H.flags reconstructed <> flags || H.hops reconstructed <> hops
      then failwith (P.sprintf "construction mismatch: %02x %02x" flags hops)
    done
  done;
  print_endline "65536 typed headers verified";
  [%expect {| 65536 typed headers verified |}]
;;

let%expect_test "typed construction rejects invalid hops" =
  let make hops =
    H.make
      ~ifac:false
      ~header_type:H.Header_1
      ~context_flag:false
      ~propagation_type:H.Broadcast
      ~destination_type:H.Single
      ~packet_type:H.Data
      ~hops
  in
  List.iter
    (fun hops ->
      try
        ignore (make hops);
        print_endline "accepted"
      with
      | Invalid_argument _ -> print_endline "rejected")
    [ -1; 256 ];
  [%expect {|
    rejected
    rejected
    |}]
;;

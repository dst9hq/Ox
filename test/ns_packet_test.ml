module H = Ox.Ns.Packet.Header
module P = Printf

let%expect_test "Reticulum header" =
  let input = Bytes.of_string "\x50\x04" in
  let h = H.decode input ~offset:0 in
  P.printf "flags: %02x\n" (H.flags h);
  P.printf "hops: %d\n" (H.hops h);
  P.printf "ifac: %b\n" (H.ifac h);
  P.printf "two addresses: %b\n" (H.two_addresses h);
  P.printf "context: %b\n" (H.context_flag h);
  P.printf "transport: %b\n" (H.transport h);
  P.printf "destination: %d\n" (H.destination_type h);
  P.printf "packet: %d\n" (H.packet_type h);
  [%expect
    {|
    flags: 50 
    hops: 4 
    ifac: false 
    two addresses: true 
    context: false 
    transport: true 
    destination: 0 
    packet: 0
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

let%expect_test "invalid headerss" =
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

module A = Ox.Ns.Address
module P = Printf

let%expect_test "two address fields" =
  let packet = Bytes.init 35 Char.chr in
  let first = A.view packet ~offset:2 in
  let second = A.view packet ~offset:18 in
  P.printf "first: %s\n" (A.to_hex first);
  P.printf "second: %s\n" (A.to_hex second);
  P.printf "equal: %b\n" (A.equal first second);
  [%expect
    {|
    first: 02030405060708090a0b0c0d0e0f1011
    second: 12131415161718191a1b1c1d1e1f2021
    equal: false
  |}]
;;

let%expect_test "view aliases original buffer" =
  let packet = Bytes.init 18 Char.chr in
  let address = A.view packet ~offset:2 in
  let snapshot = A.copy address in
  Bytes.set packet 2 '\xff';
  P.printf "view: %02x\n" (A.get address 0);
  P.printf "copy: %02x\n" (Bytes.get_uint8 snapshot 0);
  [%expect {|
    view: ff
    copy: 02
    |}]
;;

let%expect_test "address boundaries" =
  let buffer = Bytes.create 17 in
  List.iter
    (fun offset ->
      let result =
        try
          ignore (A.view buffer ~offset);
          "valid"
        with
        | Invalid_argument _ -> "invalid"
      in
      P.printf "%d: %s\n" offset result)
    [ -1; 0; 1; 2 ];
  [%expect
    {|
    -1: invalid
    0: valid
    1: valid
    2: invalid
    |}]
;;

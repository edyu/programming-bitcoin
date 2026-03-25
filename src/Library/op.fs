module op

[<Literal>]
let OP_0 = 0uy
[<Literal>]
let OP_PUSHDATA1 = 76uy
[<Literal>]
let OP_PUSHDATA2 = 77uy
[<Literal>]
let OP_PUSHDATA4 = 78uy
[<Literal>]
let OP_1NEGATE = 79uy
[<Literal>]
let OP_1 = 81uy
[<Literal>]
let OP_2 = 82uy
[<Literal>]
let OP_3 = 83uy
[<Literal>]
let OP_4 = 84uy
[<Literal>]
let OP_5 = 85uy
[<Literal>]
let OP_6 = 86uy
[<Literal>]
let OP_7 = 87uy
[<Literal>]
let OP_8 = 88uy
[<Literal>]
let OP_9 = 89uy
[<Literal>]
let OP_10 = 90uy
[<Literal>]
let OP_11 = 91uy
[<Literal>]
let OP_12 = 92uy
[<Literal>]
let OP_13 = 93uy
[<Literal>]
let OP_14 = 94uy
[<Literal>]
let OP_15 = 95uy
[<Literal>]
let OP_16 = 96uy
[<Literal>]
let OP_NOP = 97uy
[<Literal>]
let OP_IF = 99uy
[<Literal>]
let OP_NOTIF = 100uy
[<Literal>]
let OP_VERIF = 101uy
[<Literal>]
let OP_VERNOTIF = 102uy
[<Literal>]
let OP_ELSE = 103uy
[<Literal>]
let OP_ENDIF = 104uy
[<Literal>]
let OP_VERIFY = 105uy
[<Literal>]
let OP_RETURN = 106uy
[<Literal>]
let OP_TOALTSTACK = 107uy
[<Literal>]
let OP_FROMALTSTACK = 108uy
[<Literal>]
let OP_2DROP = 109uy
[<Literal>]
let OP_2DUP = 110uy
[<Literal>]
let OP_3DUP = 111uy
[<Literal>]
let OP_2OVER = 112uy
[<Literal>]
let OP_2ROT = 113uy
[<Literal>]
let OP_2SWAP = 114uy
[<Literal>]
let OP_IFDUP = 115uy
[<Literal>]
let OP_DEPTH = 116uy
[<Literal>]
let OP_DROP = 117uy
[<Literal>]
let OP_DUP = 118uy
[<Literal>]
let OP_NIP = 119uy
[<Literal>]
let OP_OVER = 120uy
[<Literal>]
let OP_PICK = 121uy
[<Literal>]
let OP_ROLL = 122uy
[<Literal>]
let OP_ROT = 123uy
[<Literal>]
let OP_SWAP = 124uy
[<Literal>]
let OP_TUCK = 125uy
[<Literal>]
let OP_SIZE = 130uy
[<Literal>]
let OP_EQUAL = 135uy
[<Literal>]
let OP_EQUALVERIFY = 136uy
[<Literal>]
let OP_1ADD = 139uy
[<Literal>]
let OP_1SUB = 140uy
[<Literal>]
let OP_2MUL = 141uy
[<Literal>]
let OP_2DIV = 142uy
[<Literal>]
let OP_NEGATE = 143uy
[<Literal>]
let OP_ABS = 144uy
[<Literal>]
let OP_NOT = 145uy
[<Literal>]
let OP_0NOTEQUAL = 146uy
[<Literal>]
let OP_ADD = 147uy
[<Literal>]
let OP_SUB = 148uy
[<Literal>]
let OP_MUL = 149uy
[<Literal>]
let OP_DIV = 150uy
[<Literal>]
let OP_MOD = 151uy
[<Literal>]
let OP_LSHIFT = 152uy
[<Literal>]
let OP_RSHIFT = 153uy
[<Literal>]
let OP_BOOLAND = 154uy
[<Literal>]
let OP_BOOLOR = 155uy
[<Literal>]
let OP_NUMEQUAL = 156uy
[<Literal>]
let OP_NUMEQUALVERIFY = 157uy
[<Literal>]
let OP_NUMNOTEQUAL = 158uy
[<Literal>]
let OP_LESSTHAN = 159uy
[<Literal>]
let OP_GREATERTHAN = 160uy
[<Literal>]
let OP_LESSTHANOREQUAL = 161uy
[<Literal>]
let OP_GREATERTHANOREQUAL = 162uy
[<Literal>]
let OP_MIN = 163uy
[<Literal>]
let OP_MAX = 164uy
[<Literal>]
let OP_WITHIN = 165uy
[<Literal>]
let OP_RIPEMD160 = 166uy
[<Literal>]
let OP_SHA1 = 167uy
[<Literal>]
let OP_SHA256 = 168uy
[<Literal>]
let OP_HASH160 = 169uy
[<Literal>]
let OP_HASH256 = 170uy
[<Literal>]
let OP_CODESEPARATOR = 171uy
[<Literal>]
let OP_CHECKSIG = 172uy
[<Literal>]
let OP_CHECKSIGVERIFY = 173uy
[<Literal>]
let OP_CHECKMULTISIG = 174uy
[<Literal>]
let OP_CHECKMULTISIGVERIFY = 175uy
[<Literal>]
let OP_NOP1 = 176uy
[<Literal>]
let OP_CHECKLOCKTIMEVERIFY = 177uy
[<Literal>]
let OP_CHECKSEQUENCEVERIFY = 178uy
[<Literal>]
let OP_NOP4 = 179uy
[<Literal>]
let OP_NOP5 = 180uy
[<Literal>]
let OP_NOP6 = 181uy
[<Literal>]
let OP_NOP7 = 182uy
[<Literal>]
let OP_NOP8 = 183uy
[<Literal>]
let OP_NOP9 = 184uy
[<Literal>]
let OP_NOP10 = 185uy

type Stack = List<byte[]>

type Cmd = Code of byte | Data of byte[]

let hex i = true

let encode_num num =
    if num = 0 then
        [||]
    else
        let mutable abs_num = abs num
        let negative = num < 0
        let mutable result = List<byte>.Empty
        while abs_num <> 0 do
            let b = byte(abs_num &&& 0xff)
            result <- b :: result
            abs_num <- abs_num >>> 8
        if List.head result &&& 0x80uy <> 0uy then
            if negative then
                result <- 0x80uy :: result
            else
                result <- 0uy :: result
        else if negative then
            result <- (List.head result ||| 0x80uy) :: List.tail result
        Array.ofList <| List.rev result

let decode_num (bytes: byte[]) : int =
    if bytes = [||] then
        0
    else
        let input = Array.rev bytes
        let mutable result = int input[0]
        let negative = input[0] &&& 0x80uy <> 0uy
        if negative then
            result <- int(input[0] &&& 0x7fuy)
        result <- helper.big_endian_to_int <| Array.concat [ [| byte result|]; input[1..] ]
        if negative then
            -result
        else
            result

let op_0 stack =
    true, encode_num 0 :: stack

let op_1negate stack =
    true, encode_num -1 :: stack

let op_1 stack =
    true, encode_num 1 :: stack

let op_2 stack =
    true, encode_num 2 :: stack

let op_3 stack =
    true, encode_num 3 :: stack

let op_4 stack =
    true, encode_num 4 :: stack

let op_5 stack =
    true, encode_num 5 :: stack

let op_6 stack =
    true, encode_num 6 :: stack

let op_7 stack =
    true, encode_num 7 :: stack

let op_8 stack =
    true, encode_num 8 :: stack

let op_9 stack =
    true, encode_num 9 :: stack

let op_10 stack =
    true, encode_num 10 :: stack

let op_11 stack =
    true, encode_num 11 :: stack

let op_12 stack =
    true, encode_num 12 :: stack

let op_13 stack =
    true, encode_num 13 :: stack

let op_14 stack =
    true, encode_num 14 :: stack

let op_15 stack =
    true, encode_num 15 :: stack

let op_16 stack =
    true, encode_num 16 :: stack

let op_nop stack =
    true, stack

let op_fail stack =
    false, stack

let op_if (stack: Stack) (cmds: Cmd list) =
    if stack.IsEmpty then
        false, stack, cmds
    else
        let mutable if_cmds = []
        let mutable else_cmds = []
        let mutable if_or_else = true
        let mutable num_endif = 1
        let mutable finished = false
        let mutable i = 0
        let mutable found = false
        while not finished do
            let cmd = List.item i cmds
            match cmd with
            | Code opcode ->
                if opcode = OP_IF || opcode = OP_NOTIF then
                    // nested if
                    num_endif <- num_endif + 1
                    if if_or_else then
                        if_cmds <- cmd :: if_cmds
                    else
                        else_cmds <- cmd :: else_cmds
                else if opcode = OP_ELSE && num_endif = 1 then
                    if_or_else <- false
                else if opcode = OP_ENDIF then
                    if num_endif = 1 then
                        finished <- true
                        found <- true
                    else
                        num_endif <- num_endif - 1
                        if if_or_else then
                            if_cmds <- cmd :: if_cmds
                        else
                            else_cmds <- cmd :: else_cmds
                else
                    if if_or_else then
                        if_cmds <- cmd :: if_cmds
                    else
                        else_cmds <- cmd :: else_cmds
            | Data data ->
                if if_or_else then
                    if_cmds <- cmd :: if_cmds
                else
                    else_cmds <- cmd :: else_cmds
        if not found then
            false, stack, cmds
        else
            if decode_num (List.head stack) = 0 then
                true, stack, else_cmds
            else
                true, stack, if_cmds

let op_notif (stack: byte[] list) (cmds: Cmd list) =
    false, stack, cmds

let op_verify (stack: Stack) =
    if stack.Length < 1 then
        false, stack
    else
        if decode_num <| List.head stack = 0 then
            false, List.tail stack
        else
            true, List.tail stack

let op_return (stack: Stack) =
    false, stack

let op_toaltstack (stack: Stack) (altstack: Stack) =
    if stack.IsEmpty then
        false, stack, altstack
    else
        true, List.tail stack, List.head stack :: altstack

let op_fromaltstack (stack: Stack) (altstack: Stack) =
    if altstack.IsEmpty then
        false, stack, altstack
    else
        true, List.head altstack :: stack, List.tail altstack

let op_2drop (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        true, List.tail <| List.tail stack

let op_2dup (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: _ ->
            true, a :: b :: stack
        | _ -> false, stack

let op_3dup (stack: Stack) =
    if stack.Length < 3 then
        false, stack
    else
        match stack with
        | a :: b :: c :: _ ->
            true, a :: b :: c :: stack
        | _ -> false, stack


let op_2over (stack: Stack) =
    if stack.Length < 4 then
        false, stack
    else
        match stack with
        | _ :: _ :: c :: d :: tail ->
            true, c :: d :: tail
        | _ -> false, stack

let op_2rot (stack: Stack) =
    if stack.Length < 6 then
        false, stack
    else
        match stack with
        | a :: b :: c :: d :: e :: f :: tail ->
            true, e :: f :: a :: b :: c :: d :: tail
        | _ -> false, stack

let op_2swap (stack: Stack) =
    if stack.Length < 4 then
        false, stack
    else
        match stack with
        | a :: b :: c :: d :: _ ->
            true, c :: d :: a :: b :: stack
        | _ -> false, stack

let op_ifdup (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        let head = List.head stack
        if decode_num head <> 0 then
            true, head :: stack
        else
            true, stack

let op_depth (stack: Stack) =
    true, encode_num stack.Length :: stack

let op_drop (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        true, List.tail stack

let op_dup (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        true, List.head stack :: stack

let op_nip (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            true, a :: tail
        | _ -> false, stack

let op_over (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | _ :: b :: _ ->
            true, b :: stack
        | _ -> false, stack

let op_pick (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | head :: tail ->
            let n = decode_num head
            if n < 0 || n >= tail.Length then
                false, tail
            else
                let newhead = List.item n tail
                true, newhead :: tail
        | _ -> false, stack

let op_roll (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | head :: tail ->
            let n = decode_num head
            if n < 0 || n >= tail.Length then
                false, tail
            else
                let newhead = List.item n tail
                true, newhead :: List.take n tail @ List.skip (n + 1) tail
        | _ -> false, stack

let op_rot (stack: Stack) =
    if stack.Length < 3 then
        false, stack
    else
        match stack with
        | a :: b :: c :: tail ->
            true, c:: a :: b :: tail
        | _ -> false, stack

let op_swap (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            true, b :: a :: tail
        | _ -> false, stack

let op_tuck (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            true, a :: b :: a :: tail
        | _ -> false, stack

let op_checksig (stack: Stack) (zbin: byte[]) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | sec_pubkey :: signature :: tail ->
            let point = ecc.S256Point.Parse sec_pubkey
            let slength = signature.Length - 1
            let sighash = signature[slength]
            let der_signature = signature[..slength-1]
            let signa = ecc.Signature.Parse der_signature
            let z = helper.bigint_from_bytes zbin
            if point.Verify z signa then
                true, encode_num 1 :: tail
            else
                true, encode_num 0 :: tail
        | _ -> false, stack

let op_checksigverify (stack: Stack) (z: byte[]) =
    let state1, newstack1 = op_checksig stack z
    let state2, newstack2 = op_verify newstack1
    state1 && state2, newstack2

let op_checkmultisig (stack: Stack) (z: byte[]) =
    false, stack

let op_checkmultisigverify (stack: Stack) (z: byte[]) =
    let state1, newstack1 = op_checkmultisig stack z
    let state2, newstack2 = op_verify newstack1
    state1 && state2, newstack2

let op_size (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        let head = List.head stack
        true, encode_num head.Length :: stack

let op_equal (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            if a = b then
                true, encode_num 1 :: tail
            else
                false, encode_num 0 :: tail
        | _ -> false, stack

let op_equalverify (stack: Stack) =
    let state1, newstack1 = op_equal stack
    let state2, newstack2 = op_verify newstack1
    state1 && state2, newstack2

let op_1add (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        let head = List.head stack
        let tail = List.tail stack
        true, encode_num (decode_num head + 1) :: tail

let op_1sub (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        let head = List.head stack
        let tail = List.tail stack
        true, encode_num (decode_num head - 1) :: tail

let op_negate (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        let head = List.head stack
        let tail = List.tail stack
        true, encode_num -(decode_num head) :: tail

let op_abs (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        let head = List.head stack
        let tail = List.tail stack
        true, encode_num (abs (decode_num head)) :: tail

let op_not (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        let head = List.head stack
        let tail = List.tail stack
        if decode_num head = 0 then
            true, encode_num 1 :: tail
        else
            true, encode_num 0 :: tail

let op_0notequal (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        let head = List.head stack
        let tail = List.tail stack
        if decode_num head = 0 then
            true, encode_num 0 :: tail
        else
            true, encode_num 1 :: tail

let op_add (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            true, encode_num (decode_num a + decode_num b) :: tail
        | _ -> false, stack

let op_sub (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            true, encode_num (decode_num b - decode_num a) :: tail
        | _ -> false, stack

let op_booland (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            let abool = decode_num a <> 0
            let bbool = decode_num b <> 0
            if abool && bbool then
                true, encode_num 1 :: tail
            else
                true, encode_num 0 :: tail
        | _ -> false, stack

let op_boolor (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            let abool = decode_num a <> 0
            let bbool = decode_num b <> 0
            if abool || bbool then
                true, encode_num 1 :: tail
            else
                true, encode_num 0 :: tail
        | _ -> false, stack

let op_numequal (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            if decode_num a = decode_num b then
                true, encode_num 1 :: tail
            else
                true, encode_num 0 :: tail
        | _ -> false, stack

let op_numequalverify (stack: Stack) =
    let state1, newstack1 = op_numequal stack
    let state2, newstack2 = op_verify newstack1
    state1 && state2, newstack2

let op_numnotequal (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            if decode_num a <> decode_num b then
                true, encode_num 1 :: tail
            else
                true, encode_num 0 :: tail
        | _ -> false, stack

let op_lessthan (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            if decode_num b < decode_num a then
                true, encode_num 1 :: tail
            else
                true, encode_num 0 :: tail
        | _ -> false, stack

let op_greaterthan (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            if decode_num b > decode_num a then
                true, encode_num 1 :: tail
            else
                true, encode_num 0 :: tail
        | _ -> false, stack

let op_lessthanorequal (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            if decode_num b <= decode_num a then
                true, encode_num 1 :: tail
            else
                true, encode_num 0 :: tail
        | _ -> false, stack

let op_greaterthanorequal (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            if decode_num b >= decode_num a then
                true, encode_num 1 :: tail
            else
                true, encode_num 0 :: tail
        | _ -> false, stack

let op_min (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            if decode_num a < decode_num b then
                true, a :: tail
            else
                true, b :: tail
        | _ -> false, stack

let op_max (stack: Stack) =
    if stack.Length < 2 then
        false, stack
    else
        match stack with
        | a :: b :: tail ->
            if decode_num a > decode_num b then
                true, a :: tail
            else
                true, b :: tail
        | _ -> false, stack

let op_within (stack: Stack) =
    if stack.Length < 3 then
        false, stack
    else
        match stack with
        | max :: min :: me :: tail ->
            let n = decode_num me
            if n >= decode_num min && n < decode_num max then
                true, encode_num 1 :: tail
            else
                true, encode_num 0 :: tail
        | _ -> false, stack

let op_ripemd160 (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        let head = List.head stack
        let tail = List.tail stack
        true, helper.ripemd160 head :: tail

let op_sha1 (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        let head = List.head stack
        let tail = List.tail stack
        true, helper.sha1 head :: tail

let op_sha256 (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        let head = List.head stack
        let tail = List.tail stack
        true, helper.sha256 head :: tail

let op_hash160 (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        let head = List.head stack
        let tail = List.tail stack
        true, helper.hash160 head :: tail

let op_hash256 (stack: Stack) =
    if stack.IsEmpty then
        false, stack
    else
        let head = List.head stack
        let tail = List.tail stack
        true, helper.hash256 head :: tail

let code_if_functions =
    Map [
        OP_IF, op_if;
        OP_NOTIF, op_notif;
    ]

let code_sig_functions =
    Map [
        OP_CHECKSIG, op_checksig;
        OP_CHECKSIGVERIFY, op_checksigverify;
        OP_CHECKMULTISIG, op_checkmultisig;
        OP_CHECKMULTISIGVERIFY, op_checkmultisigverify;
    ]

let code_altstack_functions =
    Map [
        OP_TOALTSTACK, op_toaltstack;
        OP_FROMALTSTACK, op_fromaltstack;
    ]

let code_functions =
    Map [
        OP_0, op_0;
        OP_1NEGATE, op_1negate;
        OP_1, op_1;
        OP_2, op_2;
        OP_3, op_3;
        OP_4, op_4;
        OP_5, op_5;
        OP_6, op_6;
        OP_7, op_7;
        OP_8, op_8;
        OP_9, op_9;
        OP_10, op_10;
        OP_11, op_11;
        OP_12, op_12;
        OP_13, op_13;
        OP_14, op_14;
        OP_15, op_15;
        OP_16, op_16;
        OP_NOP, op_nop;
        OP_VERIF, op_fail;
        OP_VERNOTIF, op_fail;
        OP_VERIFY, op_verify;
        OP_RETURN, op_return;
        OP_2DROP, op_2drop;
        OP_2DUP, op_2dup;
        OP_3DUP, op_3dup;
        OP_2OVER, op_2over;
        OP_2ROT, op_2rot;
        OP_2SWAP, op_2swap;
        OP_IFDUP, op_ifdup;
        OP_DEPTH, op_depth;
        OP_DROP, op_drop;
        OP_DUP, op_dup;
        OP_NIP, op_nip;
        OP_OVER, op_over;
        OP_PICK, op_pick;
        OP_ROLL, op_roll;
        OP_ROT, op_rot;
        OP_SWAP, op_swap;
        OP_TUCK, op_tuck;
        OP_SIZE, op_size;
        OP_EQUAL, op_equal;
        OP_EQUALVERIFY, op_equalverify;
        OP_1ADD, op_1add;
        OP_1SUB, op_1sub;
        OP_2MUL, op_fail;
        OP_2DIV, op_fail;
        OP_NEGATE, op_negate;
        OP_ABS, op_abs;
        OP_NOT, op_not;
        OP_0NOTEQUAL, op_0notequal;
        OP_ADD, op_add;
        OP_SUB, op_sub;
        OP_MUL, op_fail;
        OP_DIV, op_fail;
        OP_MOD, op_fail;
        OP_BOOLAND, op_booland;
        OP_BOOLOR, op_boolor;
        OP_NUMEQUAL, op_numequal;
        OP_NUMEQUALVERIFY, op_numequalverify;
        OP_NUMNOTEQUAL, op_numnotequal;
        OP_LESSTHAN, op_lessthan;
        OP_GREATERTHAN, op_greaterthan;
        OP_LESSTHANOREQUAL, op_lessthanorequal;
        OP_GREATERTHANOREQUAL, op_greaterthanorequal;
        OP_MIN, op_min;
        OP_MAX, op_max;
        OP_WITHIN, op_within;
        OP_RIPEMD160, op_ripemd160;
        OP_SHA1, op_sha1;
        OP_SHA256, op_sha256;
        OP_HASH160, op_hash160;
        OP_HASH256, op_hash256;
        176uy, op_nop;
//     177, op_checklocktimeverify;
//     178, op_checksequenceverify;
        179uy, op_nop;
        180uy, op_nop;
        181uy, op_nop;
        182uy, op_nop;
        183uy, op_nop;
        184uy, op_nop;
        185uy, op_nop;
    ]

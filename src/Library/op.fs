module op

type Cmd = Code of byte | Data of byte[]

let hex i = true

let encode_num num =
    if num = 0 then
        [| 0uy |]
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
        Array.ofList <| result

let decode_num input =
    if input = [] then
        0
    else
        let mutable result = int input[0]
        let negative = input[0] &&& 0x80uy = 0uy
        if negative then
            result <- int(input[0] &&& 0x7fuy)
        result <- helper.big_endian_to_int <| Array.ofList input[1..]
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

let op_dup (stack: Cmd list) =
    if stack.IsEmpty then
        false, stack
    else
        true, List.head stack :: stack

let op_hash256 (stack: Cmd list) =
    if stack.IsEmpty then
        false, stack
    else
        match List.head stack with
        | Data bytes -> true, Data (helper.hash256 bytes) :: List.tail stack
        | _ -> failwith "wrong stack data"

let op_hash160 (stack: Cmd list) =
    if stack.IsEmpty then
        false, stack
    else
        match List.head stack with
        | Data bytes -> true, Data (helper.hash160 bytes) :: List.tail stack
        | _ -> failwith "wrong stack data"

let OP_PUSHDATA1 = 76uy
let OP_PUSHDATA2 = 77uy

// let op_code_functions =
//     Map [
//        0, op_0;
//     79, op_1negate;
//     81, op_1;
//     82, op_2;
//     83, op_3;
//     84, op_4;
//     85, op_5;
//     86, op_6;
//     87, op_7;
//     88, op_8;
//     89, op_9;
//     90, op_10;
//     91, op_11;
//     92, op_12;
//     93, op_13;
//     94, op_14;
//     95, op_15;
//     96, op_16;
//     97, op_no;
//     99, op_if;
//     100, op_notif;
//     105, op_verify;
//     106, op_return;
//     107, op_toaltstack;
//     108, op_fromaltstack;
//     109, op_2drop;
//     110, op_2dup;
//     111, op_3dup;
//     112, op_2over;
//     113, op_2rot;
//     114, op_2swap;
//     115, op_ifdup;
//     116, op_depth;
//     117, op_drop;
//     118, op_dup;
//     119, op_nip;
//     120, op_over;
//     121, op_pick;
//     122, op_roll;
//     123, op_rot;
//     124, op_swap;
//     125, op_tuck;
//     130, op_size;
//     135, op_equal;
//     136, op_equalverify;
//     139, op_1add;
//     140, op_1sub;
//     143, op_negate;
//     144, op_abs;
//     145, op_not;
//     146, op_0notequal;
//     147, op_add;
//     148, op_sub;
//     149, op_mul;
//     154, op_booland;
//     155, op_boolor;
//     156, op_numequal;
//     157, op_numequalverify;
//     158, op_numnotequal;
//     159, op_lessthan;
//     160, op_greaterthan;
//     161, op_lessthanorequal;
//     162, op_greaterthanorequal;
//     163, op_min;
//     164, op_max;
//     165, op_within;
//     166, op_ripemd160;
//     167, op_sha1;
//     168, op_sha256;
//     169, op_hash160;
//     170, op_hash256;
//     172, op_checksig;
//     173, op_checksigverify;
//     174, op_checkmultisig;
//     175, op_checkmultisigverify;
//     176, op_nop;
//     177, op_checklocktimeverify;
//     178, op_checksequenceverify;
//     179, op_nop;
//     180, op_nop;
//     181, op_nop;
//     182, op_nop;
//     183, op_nop;
//     184, op_nop;
//     185, op_nop;
//     ]

// | op_0 = 0
// | op_1negate = 79
// | op_1 = 81 // 0x51
// | op_2 = 82
// | op_3 = 83
// | op_4 = 84
// | op_5 = 85
// | op_6 = 86
// | op_7 = 87
// | op_8 = 88
// | op_9 = 89
// | op_10 = 90
// | op_11 = 91
// | op_12 = 92
// | op_13 = 93
// | op_14 = 94
// | op_15 = 95
// | op_16 = 96 // 0x60
// | op_nop = 97
// | op_if = 99
// | op_notif = 100
// | op_verify = 105
// | op_return = 106
// | op_toaltstack = 107
// | op_fromaltstack = 108
// | op_2drop = 109
// | op_2dup = 110
// | op_3dup = 111
// | op_2over = 112
// | op_2rot = 113
// | op_2swap = 114
// | op_ifdup = 115
// | op_depth = 116
// | op_drop = 117
// | op_dup = 118 // 0x76
// | op_nip = 119
// | op_over = 120
// | op_pick = 121
// | op_roll = 122
// | op_rot = 123
// | op_swap = 124
// | op_tuck = 125
// | op_size = 130
// | op_equal = 135
// | op_equalverify = 136
// | op_1add = 139
// | op_1sub = 140
// | op_negate = 143
// | op_abs = 144
// | op_not = 145
// | op_0notequal = 146
// | op_add = 147 // ox93
// | op_sub = 148
// | op_mul = 149
// | op_booland = 154
// | op_boolor = 155
// | op_numequal = 156
// | op_numequalverify = 157
// | op_numnotequal = 158
// | op_lessthan = 159
// | op_greaterthan = 160
// | op_lessthanorequal = 161
// | op_greaterthanorequal = 162
// | op_min = 163
// | op_max = 164
// | op_within = 165
// | op_ripemd160 = 166
// | op_sha1 = 167
// | op_sha256 = 168
// | op_hash160 = 169 // 0xa9
// | op_hash256 = 170
// | op_checksig = 172 // 0xac
// | op_checksigverify = 173
// | op_checkmultisig = 174
// | op_checkmultisigverify = 175
// | op_nop = 176
// | op_checklocktimeverify = 177
// | op_checksequenceverify = 178
// | op_nop = 179
// | op_nop = 180
// | op_nop = 181
// | op_nop = 182
// | op_nop = 183
// | op_nop = 184
// | op_nop = 185


// type op_code_names =
// | "OP_0" = 0
// | "OP_PUSHDATA1" = 76
// | "OP_PUSHDATA2" = 77
// | "OP_PUSHDATA4" = 78
// | "OP_1NEGATE" = 79
// | "OP_1" = 81
// | "OP_2" = 82
// | "OP_3" = 83
// | "OP_4" = 84
// | "OP_5" = 85
// | "OP_6" = 86
// | "OP_7" = 87
// | "OP_8" = 88
// | "OP_9" = 89
// | "OP_10" = 90
// | "OP_11" = 91
// | "OP_12" = 92
// | "OP_13" = 93
// | "OP_14" = 94
// | "OP_15" = 95
// | "OP_16" = 96
// | "OP_NOP" = 97
// | "OP_IF" = 99
// | "OP_NOTIF" = 100
// | "OP_ELSE" = 103
// | "OP_ENDIF" = 104
// | "OP_VERIFY" = 105
// | "OP_RETURN" = 106
// | "OP_TOALTSTACK" = 107
// | "OP_FROMALTSTACK" = 108
// | "OP_2DROP" = 109
// | "OP_2DUP" = 110
// | "OP_3DUP" = 111
// | "OP_2OVER" = 112
// | "OP_2ROT" = 113
// | "OP_2SWAP" = 114
// | "OP_IFDUP" = 115
// | "OP_DEPTH" = 116
// | "OP_DROP" = 117
// | "OP_DUP" = 118
// | "OP_NIP" = 119
// | "OP_OVER" = 120
// | "OP_PICK" = 121
// | "OP_ROLL" = 122
// | "OP_ROT" = 123
// | "OP_SWAP" = 124
// | "OP_TUCK" = 125
// | "OP_SIZE" = 130
// | "OP_EQUAL" = 135
// | "OP_EQUALVERIFY" = 136
// | "OP_1ADD" = 139
// | "OP_1SUB" = 140
// | "OP_NEGATE" = 143
// | "OP_ABS" = 144
// | "OP_NOT" = 145
// | "OP_0NOTEQUAL" = 146
// | "OP_ADD" = 147
// | "OP_SUB" = 148
// | "OP_MUL" = 149
// | "OP_BOOLAND" = 154
// | "OP_BOOLOR" = 155
// | "OP_NUMEQUAL" = 156
// | "OP_NUMEQUALVERIFY" = 157
// | "OP_NUMNOTEQUAL" = 158
// | "OP_LESSTHAN" = 159
// | "OP_GREATERTHAN" = 160
// | "OP_LESSTHANOREQUAL" = 161
// | "OP_GREATERTHANOREQUAL" = 162
// | "OP_MIN" = 163
// | "OP_MAX" = 164
// | "OP_WITHIN" = 165
// | "OP_RIPEMD160" = 166
// | "OP_SHA1" = 167
// | "OP_SHA256" = 168
// | "OP_HASH160" = 169
// | "OP_HASH256" = 170
// | "OP_CODESEPARATOR" = 171
// | "OP_CHECKSIG" = 172
// | "OP_CHECKSIGVERIFY" = 173
// | "OP_CHECKMULTISIG" = 174
// | "OP_CHECKMULTISIGVERIFY" = 175
// | "OP_NOP1" = 176
// | "OP_CHECKLOCKTIMEVERIFY" = 177
// | "OP_CHECKSEQUENCEVERIFY" = 178
// | "OP_NOP4" = 179
// | "OP_NOP5" = 180
// | "OP_NOP6" = 181
// | "OP_NOP7" = 182
// | "OP_NOP8" = 183
// | "OP_NOP9" = 184
// | "OP_NOP10" = 185

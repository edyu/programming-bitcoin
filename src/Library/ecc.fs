module ecc

open System.Globalization
open System.Numerics
open System.Security.Cryptography

let P: bigint = BigInteger.Pow(2, 256) - BigInteger.Pow(2, 32) - 977I
let Pminus: bigint = P - 1I

let N: bigint = helper.bigint_from_hex "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

type S256Field = private { num: bigint; prime: bigint } with
    member this.Num = this.num
    member this.Prime = this.prime
    member this.sqrt = this *^ ((P + 1I) / 4I)
    override this.ToString() = this.num.ToString()
    static member Create Num =
        if Num >= P || Num  < 0I then
            invalidArg "Num" $"Num {Num} not in field range 0 to {P-1I}"
        else
            { num = Num; prime = P }
    static member (+) (a, b: S256Field) =
        { num = (a.num + b.num) % P; prime = P }
    static member (-) (a, b: S256Field) =
        let d = (a.num - b.num + P) % P
        { num = d; prime = P }
    static member (*) (a, b: S256Field) =
        { num = a.num * b.num % P; prime = P }
    static member (*) (a: S256Field, b: int) =
        { num = a.num * bigint b % P; prime = P }
    static member (*) (a: int, b: S256Field) =
        b * a
    static member ( *^ ) (a: S256Field, e: bigint) =
        let n = (e % Pminus + Pminus) % Pminus
        let nn = BigInteger.ModPow(a.num, n, P)
        { num = nn; prime = P }
    static member (/) (a, b: S256Field) =
        a * (b *^ -1I)

let A = S256Field.Create 0I
let B = S256Field.Create 7I

let GX = S256Field.Create <| BigInteger.Parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", NumberStyles.HexNumber)
let GY = S256Field.Create <| BigInteger.Parse("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", NumberStyles.HexNumber)

type Signature = { r: bigint; s: bigint } with
    override this.ToString() =
        $"Signature({helper.bigint_to_hex this.r},{helper.bigint_to_hex this.s})"
    member this.Der =
        let mutable rbin = helper.bigint_to_bytes this.r
        rbin <- helper.lstrip rbin 0uy
        if rbin[0] >= 0x80uy then
            rbin <- Array.concat [ [| 0uy |]; rbin ]
        let mutable result = Array.concat [ [| 2uy; byte rbin.Length |]; rbin ]
        let mutable sbin = helper.bigint_to_bytes this.s
        sbin <- helper.lstrip sbin 0uy
        if sbin[0] >= 0x80uy then
            sbin <- Array.concat [ [| 0uy |]; sbin ]
        result <- Array.concat [ result; [| 2uy; byte sbin.Length |]; sbin ]
        Array.concat [ [| 0x30uy; byte result.Length |]; result ]

type S256Point = private { x: S256Field option; y: S256Field option; a: S256Field; b: S256Field } with
    static member Infinity =
        { x = None; y = None; a = A; b = B }
    static member G =
        { x = Some GX; y = Some GY; a = A; b = B }
    member this.X = (Option.get this.x).Num
    member this.Y = (Option.get this.y).Num
    member this.A = this.a
    member this.B = this.b
    member this.IsInfinity = this.x = None

    member this.Sec (?compressed0: bool) =
        let compressed = defaultArg compressed0 true
        if compressed then
            let prefix =
                if this.Y.IsEven then
                    Array.create 1 02uy
                else
                    Array.create 1 03uy
            Array.concat [
                    prefix;
                    helper.bigint_to_bytes this.X;
                ]
        else
            let prefix = Array.create 1 04uy
            Array.concat [
                    prefix;
                    helper.bigint_to_bytes this.X;
                    helper.bigint_to_bytes this.Y
                ]

    member this.hash160 (?compressed0: bool) =
        let compressed = defaultArg compressed0 true
        this.Sec compressed |> helper.hash160

    member this.Address (?compressed0: bool, ?testnet0: bool) =
        let compressed = defaultArg compressed0 true
        let testnet = defaultArg testnet0 false
        let h160 = this.hash160 compressed
        let prefix = if testnet then [| 0x6fuy |] else [| 0x00uy |]
        helper.base58_checksum <| Array.concat [ prefix; h160 ]

    member this.Verify z (sign: Signature) =
        let s_inv = bigint.ModPow(sign.s, N - 2I, N)
        let u = z * s_inv % N
        let v = sign.r * s_inv % N
        let R = u * S256Point.G + v * this
        if R.IsInfinity then false
        else R.X = sign.r

    override this.ToString() =
        if this.IsInfinity then
            $"S256Point(Inf,Inf)"
        else
            $"S256Point({helper.bigint_to_hex this.X}, {helper.bigint_to_hex this.Y})"

    static member Create x y =
        let X = S256Field.Create x
        let Y = S256Field.Create y
        if Y * Y <> X * X * X + A * X + B then
            invalidArg "x y" $"({X}, {Y}) is not on the curve"
        else
            { x = Some X; y = Some Y; a = A; b = B }

    static member (+) (self, other: S256Point) : S256Point =
        if self.a <> other.a || self.b <> other.b then
            failwith $"Points {self}, {other} are not the same curve"
        match self.x, self.y, other.x, other.y with
            | None, _, _, _ | _, None, _, _  -> other
            | _, _, None, _ | _, _, _, None -> self
            | Some x1, Some y1, Some x2, Some y2 when x1 = x2 && y1 <> y2 ->
                { x = None; y = None; a = self.a; b = self.b }
            | Some x1, Some y1, Some x2, Some y2 when x1 = x2 && y1 = y2 ->
                if y1.Num = 0I then
                    { x = None; y = None; a = self.a; b = self.b }
                else
                    let s = (3 * x1 * x1 + self.a) / (2 * y1)
                    let x = s * s - 2 * x1
                    let y = s * (x1 - x) - y1
                    { x = Some x; y = Some y; a = self.a; b = self.b }
            | Some x1, Some y1, Some x2, Some y2 ->
                let s = (y2 - y1) / (x2 - x1)
                let x = s * s - x1 - x2
                let y = s * (x1 - x) - y1
                { x = Some x; y = Some y; a = self.a; b = self.b }

    static member (*) (coeff: bigint, self: S256Point) : S256Point =
        let mutable coef = coeff % N
        let mutable current = self
        let mutable result = S256Point.Infinity
        while coef <> 0I do
            if coef &&& 1I <> 0I then
                result <- result + current
            current <- current + current
            coef <- coef >>> 1
        result

    static member Parse (sec_bin: byte[]) =
        if sec_bin[0] = 4uy then
            let x = helper.bigint_from_bytes sec_bin[1..32]
            let y = helper.bigint_from_bytes sec_bin[33..64]
            S256Point.Create x y
        else
            let is_even = sec_bin[0] = 2uy
            let x = S256Field.Create <| helper.bigint_from_bytes sec_bin[1 ..]
            // y^2 = x^3 + 7
            let alpha = x *^ 3I + B
            let beta = alpha.sqrt
            let mutable even_beta = beta
            let mutable odd_beta = beta
            if beta.Num.IsEven then
                odd_beta <- S256Field.Create (P - beta.Num)
            else
                even_beta <- S256Field.Create (P - beta.Num)
            if is_even then
                { x = Some x; y = Some even_beta; a = A; b = B }
            else
                { x = Some x; y = Some odd_beta; a = A; b = B }

type PrivateKey = private { secret: bigint; point: S256Point } with
    member this.Point = this.point

    member this.hex =
        helper.bigint_to_hex this.secret

    member private this.deterministic_k z =
        let mutable k = Array.create 32 0uy
        let mutable v = Array.create 32 1uy
        let zz = if z > N then z - N else z
        let z_bytes = helper.bigint_to_bytes zz
        let s_bytes = helper.bigint_to_bytes this.secret
        let zero = Array.create 1 0uy
        let one = Array.create 1 1uy
        k <- HMACSHA256.HashData(k, Array.concat [ v; zero; s_bytes; z_bytes ])
        v <- HMACSHA256.HashData(k, v)
        k <- HMACSHA256.HashData(k, Array.concat [ v; one; s_bytes; z_bytes ])
        v <- HMACSHA256.HashData(k, v)
        let mutable loop = true
        let mutable result = 0I
        while loop do
            v <- HMACSHA256.HashData(k, v)
            result <- helper.bigint_from_bytes v
            if result >= 1I && result < N then
                loop <- false
            else
                k <- HMACSHA256.HashData(k, Array.concat [ v; zero ])
                v <- HMACSHA256.HashData(k, v)
        result

    member this.Wif (?compressed0: bool, ?testnet0: bool) =
        let compressed = defaultArg compressed0 true
        let testnet = defaultArg testnet0 false
        let bytes = helper.bigint_to_bytes this.secret
        let prefix = if testnet then [| 0xefuy |] else [| 0x80uy |]
        let suffix = if compressed then [| 0x01uy |] else [||]
        helper.base58_checksum <| Array.concat [ prefix; bytes; suffix ]

    member this.Sign z =
        let k = this.deterministic_k z
        let r = (k * S256Point.G).X
        let k_inv = bigint.ModPow(k, N - 2I, N)
        let mutable s = (z + r * this.secret) * k_inv % N
        if s > N / 2I then
            s <- N - s
        { r = r; s = s}

    static member Create s =
        { secret = s; point = s * S256Point.G }

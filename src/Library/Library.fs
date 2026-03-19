module Library

open System
open System.Numerics
open System.Globalization
open System.Security.Cryptography
open System.Text

module helper =
    let private bigint_to_hex_internal (b: bigint) (prefix: bool) (lead: bool)=
        let s = b.ToString "x64"
        let len = String.length s
        let mutable ss = s.Substring(len-64, 64)
        if not lead then
            while ss.StartsWith "0" do
                ss <- ss[1..]
        if prefix then
            "0x" + ss
        else
            ss

    let bigint_to_hex (b: bigint) = bigint_to_hex_internal b false true

    let hex i = bigint_to_hex_internal i true false

    let bigint_from_hex (hex: string) =
        let s = if hex[0..1] = "0x" then hex[2..] else hex
        let lead = System.Int32.Parse(s[0..1], NumberStyles.HexNumber)
        if lead >= 0x80 then // make sure it's positive
            BigInteger.Parse("0" + s, NumberStyles.HexNumber)
        else
            BigInteger.Parse(s, NumberStyles.HexNumber)

    let hash256 (input: string) =
        use sha256 = SHA256.Create()
        let bytes = Encoding.UTF8.GetBytes input
        sha256.ComputeHash bytes |> sha256.ComputeHash

    let bytes_to_hex bytes =
        BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant()

    let bytes_from_hex (hex: string) =
        Convert.FromHexString hex

    let bigint_from_bytes bytes =
        bytes_to_hex bytes |> bigint_from_hex

    let bigint_to_bytes (i: bigint) =
        let result = Array.create 32 0uy
        let bytes = i.ToByteArray()
        let len = min bytes.Length 32
        Array.Copy(bytes, result, len)
        Array.Reverse result
        result

    let rand_bigint (max: bigint) =
        let b = RandomNumberGenerator.GetBytes 32
        if max <= 0I then
            bigint_from_bytes b
        else
            bigint_from_bytes b % max

    let lstrip (bytes: byte[]) (pre: byte) : byte[] =
        let index = Array.FindIndex(bytes, fun b -> b <> pre)
        if index = -1 then
            Array.Empty()
        else
            bytes[index..]

    let BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    let base58 (s: byte[]) =
        let mutable count = Array.FindIndex(s, fun b -> b <> 0uy)
        if count < 0 then count <- 0
        let mutable num = bigint_from_bytes s
        let prefix = String.replicate count "1"
        let mutable result = ""
        let mutable rem = 0I
        while num > 0I do
            let (q, r) = bigint.DivRem(num, 58)
            num <- q
            rem <- r
            result <- string BASE58_ALPHABET[int rem] + result
        prefix + result

type FieldElement = private { num: int; prime: int } with
    member this.Num = this.num
    member this.Prime = this.prime
    override this.ToString() = $"FieldElement_{this.Prime}({this.Num})"
    static member Create Num Prime =
        if Num >= Prime || Num  < 0 then
            invalidArg "Num" $"Num {Num} not in field range 0 to {Prime-1}"
        else
            { num = Num; prime = Prime }
    static member (+) (a, b: FieldElement) =
        if a.prime <> b.prime then
            failwith "Cannot add two numbers in different Fields"
        { num = (a.num + b.num) % a.prime; prime = a.prime }
    static member (-) (a, b: FieldElement) =
        if a.prime <> b.prime then
            failwith "Cannot subtract two numbers in different Fields"
        let d = (a.num - b.num + a.prime) % a.prime
        { num = d; prime = a.prime }
    static member (*) (a, b: FieldElement) =
        if a.prime <> b.prime then
            failwith "Cannot multiply two numbers in different Fields"
        { num = a.num * b.num % a.prime; prime = a.prime }
    static member (*) (a: FieldElement, b: int) =
        { num = a.num * b % a.prime; prime = a.prime }
    static member (*) (a: int, b: FieldElement) =
        b * a
    static member ( *^ ) (a: FieldElement, e) =
        let n = (e % (a.prime - 1) + (a.prime - 1)) % (a.prime - 1) 
        let bn = bigint a.num
        let nn = int(pown bn n % bigint a.prime)
        { num = nn; prime = a.prime }
    static member (/) (a, b: FieldElement) =
        if a.prime <> b.prime then
            failwith "Cannot divide two numbers in different Fields"
        a * (b *^ -1)

type IntPoint = private { x: int option; y: int option; a: int; b: int  } with
    member this.X = this.x
    member this.Y = this.y
    member this.A = this.a
    member this.B = this.b
    member this.IsInfinity = this.x = None
    static member Infinity A B =
        { x = None; y = None; a = A; b = B }
    static member Create X Y A B =
        if Y * Y <> X * X * X + A * X + B then
            invalidArg "x y" $"({X}, {Y}) is not on the curve"
        else
            { x = Some X; y = Some Y; a = A; b = B }
    static member (+) (self, other: IntPoint) =
        if self.a <> other.a || self.b <> other.b then
            failwith $"Points {self}, {other} are not the same curve"
        match self.x, self.y, other.x, other.y with
            | None, _, _, _ | _, None, _, _  -> other
            | _, _, None, _ | _, _, _, None -> self
            | Some x1, Some y1, Some x2, Some y2 when x1 = x2 && y1 <> y2 ->
                { x = None; y = None; a = self.a; b = self.b }
            | Some x1, Some y1, Some x2, Some y2 when x1 = x2 && y1 = y2 ->
                if y1 = 0 then
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

type Point = private { x: FieldElement option; y: FieldElement option; a: FieldElement; b: FieldElement } with
    member this.X = this.x
    member this.Y = this.y
    member this.A = this.a
    member this.B = this.b
    member this.IsInfinity = this.x = None
    override this.ToString() =
        if this.IsInfinity then
            $"Point(Inf,Inf)_{this.a.num}_{this.b.num} FieldElement({this.a.prime})"
        else
            match this.X, this.Y with
                | Some x, Some y ->
                    $"Point({x.num},{y.num})_{this.a.num}_{this.b.num} FieldElement({this.a.prime})"
                | _, _ -> failwith $"{this} is invalid"
    static member Infinity A B =
        { x = None; y = None; a = A; b = B }
    static member Create X Y A B =
        if Y * Y <> X * X * X + A * X + B then
            invalidArg "x y" $"({X}, {Y}) is not on the curve"
        else
            { x = Some X; y = Some Y; a = A; b = B }
    static member (+) (self, other: Point) : Point =
        if self.a <> other.a || self.b <> other.b then
            failwith $"Points {self}, {other} are not the same curve"
        match self.x, self.y, other.x, other.y with
            | None, _, _, _ | _, None, _, _  -> other
            | _, _, None, _ | _, _, _, None -> self
            | Some x1, Some y1, Some x2, Some y2 when x1 = x2 && y1 <> y2 ->
                { x = None; y = None; a = self.a; b = self.b }
            | Some x1, Some y1, Some x2, Some y2 when x1 = x2 && y1 = y2 ->
                if y1.Num = 0 then
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
    static member (*) (coeff: int, self: Point) : Point =
        let mutable coef = coeff
        let mutable current = self
        let mutable result = Point.Infinity self.A self.B
        while coef <> 0 do
            if coef &&& 1 <> 0 then
                result <- result + current
            current <- current + current
            coef <- coef >>> 1
        result

module ecc =
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

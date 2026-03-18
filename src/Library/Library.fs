module Library

//module ecc
open System.Numerics
open System.Globalization

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
        { num = (a.num * b.num) % a.prime; prime = a.prime }
    static member (*) (a: FieldElement, b: int) =
        { num = (a.num * b) % a.prime; prime = a.prime }
    static member (*) (a: int, b: FieldElement) =
        b * a
    static member ( *^ ) (a: FieldElement, e) =
        let n = (e % (a.prime - 1) + (a.prime - 1)) % (a.prime - 1) 
        let bn = bigint(a.num)
        let nn = int((pown bn n) % bigint(a.prime))
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
    member this.isInfinity = this.x = None
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
    member this.isInfinity = this.x = None
    override this.ToString() =
        if this.isInfinity then
            $"Point(Inf,Inf)_{this.a.num}_{this.b.num} FieldElement({this.a.prime})"
        else
            match (this.X, this.Y) with
                | (Some x, Some y) ->
                    $"Point({x.num},{y.num})_{this.a.num}_{this.b.num} FieldElement({this.a.prime})"
                | (_, _) -> failwith $"{this} is invalid"
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

let bigint_tohex (b: bigint) =
    let s = b.ToString("X64")
    let len = String.length(s)
    s.Substring(len-64, 64)

let bigint_fromhex (hex: string) =
    let s = if hex[0..1] = "0x" then hex[2..] else hex
    let lead = System.Int32.Parse(s[0..1], NumberStyles.HexNumber)
    if lead >= 0x80 then // make sure it's positive
        BigInteger.Parse("0" + s, NumberStyles.HexNumber)
    else
        BigInteger.Parse(s, NumberStyles.HexNumber)

let P: bigint = BigInteger.Pow(2, 256) - BigInteger.Pow(2, 32) - bigint(977)
let Pminus: bigint = P - bigint(1)

type S256Field = private { num: bigint; prime: bigint } with
    member this.Num = this.num
    member this.Prime = this.prime
    override this.ToString() = this.num.ToString()
    static member Create Num =
        if Num >= P || Num  < bigint(0) then
            invalidArg "Num" $"Num {Num} not in field range 0 to {P-bigint(1)}"
        else
            { num = Num; prime = P }
    static member (+) (a, b: S256Field) =
        { num = (a.num + b.num) % P; prime = P }
    static member (-) (a, b: S256Field) =
        let d = (a.num - b.num + P) % P
        { num = d; prime = P }
    static member (*) (a, b: S256Field) =
        { num = (a.num * b.num) % P; prime = P }
    static member (*) (a: S256Field, b: int) =
        { num = (a.num * bigint(b)) % P; prime = P }
    static member (*) (a: int, b: S256Field) =
        b * a
    static member ( *^ ) (a: S256Field, e: bigint) =
        let n = (e % Pminus + Pminus) % Pminus
        let nn = BigInteger.ModPow(a.num, n, P)
        { num = nn; prime = P }
    static member (/) (a, b: S256Field) =
        a * (b *^ bigint(-1))

let A = S256Field.Create(bigint(0))
let B = S256Field.Create(bigint(7))
let N: bigint = bigint_fromhex "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

type Signature = { r: bigint; s: bigint } with
    override this.ToString() =
        $"Signature({bigint_tohex this.r},{bigint_tohex this.s})"

let GX = S256Field.Create <| BigInteger.Parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", NumberStyles.HexNumber)
let GY = S256Field.Create <| BigInteger.Parse("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", NumberStyles.HexNumber)

type S256Point = private { x: S256Field option; y: S256Field option; a: S256Field; b: S256Field } with
    static member Infinity =
        { x = None; y = None; a = A; b = B }
    static member G =
        { x = Some GX; y = Some GY; a = A; b = B }
    member this.X = this.x
    member this.Y = this.y
    member this.A = this.a
    member this.B = this.b
    member this.isInfinity = this.x = None

    member this.verify z (sign: Signature) =
        let s_inv = bigint.ModPow(sign.s, (N-bigint(2)), N)
        let u = z * s_inv % N
        let v = sign.r * s_inv % N
        let R = u * S256Point.G + v * this
        match R.X with
            | (Some x) -> x.Num = sign.r
            | _ -> false

    override this.ToString() =
        if this.isInfinity then
            $"S256Point(Inf,Inf)"
        else
            match (this.X, this.Y) with
                | (Some x, Some y) ->
                    $"S256Point({x.num},{y.num})"
                | (_, _) -> failwith $"{this} is invalid"

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
                if y1.Num = bigint(0) then
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
        while coef <> bigint(0) do
            if coef &&& bigint(1) <> bigint(0) then
                result <- result + current
            current <- current + current
            coef <- coef >>> 1
        result

let verify z r s (p: S256Point) =
    let s_inv = bigint.ModPow(s, (N-bigint(2)), N)
    let u = z * s_inv % N
    let v = r * s_inv % N
    let R = u * S256Point.G + v * p
    match R.X with
        | (Some x) -> x.Num = r
        | _ -> false


module network

open System
open System.Text
open System.IO
open System.Net

let NETWORK_MAGIC = [| 0xf9uy; 0xbeuy; 0xb4uy; 0xd9uy |]
let TESTNET_NETWORK_MAGIC = [| 0x0buy; 0x11uy; 0x09uy; 0x07uy |]

type Address = IP of IPAddress | Raw of byte array

type NetworkEnvelope = { command: byte array; payload: byte array; testnet: bool } with
    member this.Command = Encoding.ASCII.GetString this.command
    member this.Payload = this.payload
    member this.Magic =
        if this.testnet then
            TESTNET_NETWORK_MAGIC
        else
            NETWORK_MAGIC

    override this.ToString() =
        $"{this.Command}: {helper.bytes_to_hex this.payload}"

    static member Create(command, payload, ?testnet0) =
        let testnet = defaultArg testnet0 false
        { command = command; payload = payload; testnet = testnet }

    static member Parse(stream: Stream, ?testnet0: bool) =
        let testnet = defaultArg testnet0 false
        let buffer4 = Array.zeroCreate<byte> 4
        let bytesRead = stream.Read(buffer4, 0, 4)
        if bytesRead <> 4 then
            failwith "connection reset!"
        let expected_magic = if testnet then TESTNET_NETWORK_MAGIC else NETWORK_MAGIC
        let magic = buffer4
        if magic <> expected_magic then
            failwith $"magic is not right {helper.bytes_to_hex magic} vs {helper.bytes_to_hex expected_magic}"
        let buffer12 = Array.zeroCreate<byte> 12
        stream.ReadExactly buffer12
        let command = buffer12 |> Array.rev |> Seq.skipWhile (fun x -> x = 0uy) |> Array.ofSeq |> Array.rev
        stream.ReadExactly buffer4
        let payload_length = int <| helper.little_endian_to_int buffer4
        stream.ReadExactly buffer4
        let checksum = buffer4
        let buffer_payload = Array.zeroCreate<byte> payload_length
        stream.ReadExactly buffer_payload
        let calculated_checksum = (helper.hash256 buffer_payload)[0..3]
        if calculated_checksum <> checksum then
            failwith "checksum does not match"
        else
            { command = command; payload = buffer_payload; testnet = testnet }

    member this.Serialize =
        let plen = 12 - this.command.Length
        let command = Array.concat [ this.command; Array.zeroCreate plen ]
        let hash = (helper.hash256 this.payload)[0..3]
        Array.concat [ this.Magic; command; helper.int_to_little_endian(uint64 this.payload.Length, 4); hash; this.payload ]

type VersionMessage = private { version: uint32; services: uint64; timestamp: uint64;
                                receiver_services: uint64; receiver_address: Address; receiver_port: uint16;
                                sender_services: uint64; sender_address: Address; sender_port: uint16;
                                nonce: byte array; user_agent: string; latest_block: uint32; relay: bool } with
    static member Command = Encoding.ASCII.GetBytes "version"
    member this.Version = this.version
    member this.Services = this.services
    member this.Timestamp = this.timestamp
    member this.ReceiverServices = this.receiver_services
    member this.ReceiverAddress = this.receiver_address
    member this.ReceiverPort = this.receiver_port
    member this.SenderServices = this.sender_services
    member this.SenderAddress = this.sender_address
    member this.SenderPort = this.sender_port
    member this.Nonce = this.nonce
    member this.UserAgent = this.user_agent
    member this.LatestBlock = this.latest_block
    member this.Relay = this.relay

    static member Create(?timestamp0: uint64 option, ?nonce0: byte array option, ?user_agent0: string,
                            ?version0: uint32, ?services0: uint64,
                            ?receiver_services0: uint64, ?receiver_address0: Address, ?receiver_port0: uint16,
                            ?sender_services0: uint64, ?sender_address0: Address, ?sender_port0: uint16,
                            ?latest_block0: uint32, ?relay0: bool) =
        let version = defaultArg version0 70015u
        let services = defaultArg services0 0UL
        let timestamp0 = defaultArg timestamp0 None
        let timestamp = match timestamp0 with
                        | None -> uint64 <| DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                        | Some t -> t
        let receiver_services = defaultArg receiver_services0 0UL
        let receiver_address = defaultArg receiver_address0 (IP <| IPAddress.Parse "0.0.0.0")
        let receiver_port = defaultArg receiver_port0 8333us
        let sender_services = defaultArg sender_services0 0UL
        let sender_address = defaultArg sender_address0 (IP <| IPAddress.Parse "0.0.0.0")
        let sender_port = defaultArg sender_port0 8333us
        let nonce0 = defaultArg nonce0 None
        let nonce = match nonce0 with
                        | None -> helper.int_to_little_endian(uint64(Random().NextInt64()), 8)
                        | Some n -> n
        let user_agent = defaultArg user_agent0 "/programmingbitcoin:0.1/"
        let latest_block = defaultArg latest_block0 0u
        let relay = defaultArg relay0 false
        { version = version; services = services; timestamp = timestamp; receiver_services = receiver_services; receiver_address = receiver_address; receiver_port = receiver_port; sender_services = sender_services; sender_address = sender_address; sender_port = sender_port; nonce = nonce; user_agent = user_agent; latest_block = latest_block; relay = relay }

    static member Parse (stream: Stream) =
        let buffer4 = Array.zeroCreate<byte> 4
        stream.ReadExactly buffer4
        let version = uint32 <| helper.little_endian_to_int buffer4
        let buffer8 = Array.zeroCreate<byte> 8
        let services = helper.little_endian_to_int buffer8
        let timestamp = helper.little_endian_to_int buffer8
        let receiver_services = helper.little_endian_to_int buffer8
        let buffer16 = Array.zeroCreate<byte> 16
        let prefix = Array.zeroCreate<byte> 10
        let marker = [|0xffuy; 0xffuy|]
        stream.ReadExactly buffer16
        let receiver_address = if buffer16[0..9] = prefix && buffer16[10..11] = marker then
                                   IP <| IPAddress(buffer16[12..15])
                               else
                                   Raw <| Array.copy buffer16
        let buffer2 = Array.zeroCreate<byte> 2
        stream.ReadExactly buffer2
        let receiver_port = uint16 <| helper.big_endian_to_int buffer2
        let sender_services = helper.little_endian_to_int buffer8
        let sender_address = if buffer16[0..9] = prefix && buffer16[10..11] = marker then
                                 IP <| IPAddress(buffer16[12..15])
                             else
                                 Raw <| Array.copy buffer16
        let sender_port = uint16 <| helper.big_endian_to_int buffer2
        stream.ReadExactly buffer8
        let nonce = buffer8
        let ua_length = helper.read_varint stream
        let ua_bytes = Array.zeroCreate<byte> <| int ua_length
        stream.ReadExactly ua_bytes
        let user_agent = Encoding.UTF8.GetString ua_bytes
        stream.ReadExactly buffer4
        let latest_block = uint32 <| helper.little_endian_to_int buffer4
        let relay = if stream.ReadByte() = 0x01 then true else false
        VersionMessage.Create (Some timestamp, Some nonce, user_agent, version, services,
            receiver_services, receiver_address, receiver_port,
            sender_services, sender_address, sender_port,
            latest_block, relay)

    member this.Serialize =
        let version = helper.int_to_little_endian(uint64 this.version, 4)
        let services = helper.int_to_little_endian(this.services, 8)
        let timestamp = helper.int_to_little_endian(this.timestamp, 8)
        let receiver_services = helper.int_to_little_endian(this.receiver_services, 8)
        let add_prefix = Array.zeroCreate 10
        let receiver_address = match this.receiver_address with
                                | IP address -> Array.concat [ add_prefix; [|0xffuy; 0xffuy|]; address.GetAddressBytes() ]
                                | Raw bytes -> bytes
        let receiver_port = helper.int_to_big_endian(int this.receiver_port, 2)
        let sender_services = helper.int_to_little_endian(this.sender_services, 8)
        let sender_address = match this.sender_address with
                                | IP address -> Array.concat [ add_prefix; [|0xffuy; 0xffuy|]; address.GetAddressBytes() ]
                                | Raw bytes -> bytes
        let sender_port = helper.int_to_big_endian(int this.sender_port, 2)
        let nonce = this.nonce
        let ua_bytes = Encoding.UTF8.GetBytes this.user_agent
        let user_agent = Array.concat [ helper.encode_varint <| uint64 ua_bytes.Length; ua_bytes ]
        let latest_block = helper.int_to_little_endian(uint64 this.latest_block, 4)
        let relay = if this.relay then [| 0x01uy |] else [| 0x00uy |]
        Array.concat [ version; services; timestamp;
                        receiver_services; receiver_address; receiver_port;
                        sender_services; sender_address; sender_port;
                        nonce; user_agent; latest_block; relay ]

type VerAckMessage = private { body: byte array } with
    static member Command = Encoding.ASCII.GetBytes "verack"
    member this.Body = this.body

    static member Create =
        { body = [||] }

    static member Parse stream =
        VerAckMessage.Create

    member this.Serialize = this.body

type PingMessage = private { nonce: byte array } with
    static member Command = Encoding.ASCII.GetBytes "ping"

    static member Create (nonce: byte array) =
        { nonce = nonce }

    static member Parse (stream: Stream) =
        let nonce = Array.zeroCreate<byte> 8
        stream.ReadExactly nonce
        PingMessage.Create nonce

    member this.Serialize = this.nonce

type PongMessage = private { nonce: byte array } with
    static member Command = Encoding.ASCII.GetBytes "pong"

    static member Create (nonce: byte array) =
        { nonce = nonce }

    static member Parse (stream: Stream) =
        let nonce = Array.zeroCreate<byte> 8
        stream.ReadExactly nonce
        PongMessage.Create nonce

    member this.Serialize = this.nonce

type GetHeadersMessage = private { version: uint32; num_hashes: int; start_block: byte array; end_block: byte array } with
    static member Command = Encoding.ASCII.GetBytes "getheaders"

    static member Create (start_block: byte array, ?version0: uint32, ?num_hashes0: int, ?end_block0: byte array) =
        let version = defaultArg version0 70015u
        let num_hashes = defaultArg num_hashes0 1
        let end_block = defaultArg end_block0 (Array.zeroCreate<byte> 32)
        { version = version; num_hashes = num_hashes; start_block = start_block; end_block = end_block }

    member this.Serialize =
        let version = helper.int_to_little_endian(uint64 this.version, 4)
        let num_hashes = helper.encode_varint <| uint64 this.num_hashes
        let start_block = Array.rev this.start_block
        let end_block = Array.rev this.end_block
        Array.concat [ version; num_hashes; start_block; end_block ]

type HeadersMessage = private { blocks: block.Block[] } with
    static member Command = Encoding.ASCII.GetBytes "headers"
    member this.Blocks = this.blocks

    static member Create (blocks: block.Block[]) =
        { blocks = blocks }

    static member Parse (stream: Stream) =
        let num_headers = int <| helper.read_varint stream
        let mutable blocks = []
        for _ in [1..num_headers] do
            let b = block.Block.Parse stream
            let num_txs = helper.read_varint stream
            if num_txs <> 0UL then
                failwith "number of transactions is not 0"
            blocks <- b :: blocks
        HeadersMessage.Create <| Array.ofList (List.rev blocks)

type DataType =
| TX = 1
| BLOCK = 2
| FILTERED_BLOCK = 3
| COMPACT_BLOCK = 4

type GetDataMessage = private { mutable data: (DataType * byte array) list } with
    static member Command = Encoding.ASCII.GetBytes "getdata"

    static member Create =
        { data = [] }

    member this.AddData (data_type: DataType) (identifier: byte array) =
        this.data <- (data_type, identifier) :: this.data

    member this.Serialize =
        let mutable result = []
        let len = helper.encode_varint <| uint64 this.data.Length
        result <- len :: result
        for data_type, identifier in List.rev this.data do
            result <- helper.int_to_little_endian(uint64 data_type, 4) :: result
            result <- Array.rev identifier :: result
        Array.concat <| List.rev result

type GenericMessage = private { command: byte array; payload: byte array } with
    member this.Command = this.command
    member this.Payload = this.payload

    static member Create (command: string, payload: byte array) =
        { command = Encoding.ASCII.GetBytes command; payload = payload }

    static member Parse (stream: Stream) =
        let clen = int <| helper.read_varint stream
        let command = Array.zeroCreate<byte> clen
        stream.ReadExactly command
        let plen = int <| helper.read_varint stream
        let payload = Array.zeroCreate<byte> plen
        stream.ReadExactly payload
        { command = command; payload = payload }

    member this.Serialize = this.Payload

// type Message = VersionMessage | VerAckMessage
type Message = Version of VersionMessage | VerAck of VerAckMessage | Ping of PingMessage | Pong of PongMessage | GetHeaders of GetHeadersMessage | Headers of HeadersMessage

type SimpleNode = private { host: string; port: int; testnet: bool; logging: bool; stream: Stream } with
    static member Create(host: string, ?testnet0: bool, ?port0: int, ?logging0: bool) =
        let testnet = defaultArg testnet0 false
        let logging = defaultArg logging0 false
        let port = if testnet then defaultArg port0 18333 else defaultArg port0 8333
        let client = new Sockets.TcpClient(host, port)
        let stream = client.GetStream()
        { host = host; port = port; testnet = testnet; logging = logging; stream = stream }

    member this.Send (message: Message) =
        let envelope = match message with
                        | VerAck m ->  NetworkEnvelope.Create(VerAckMessage.Command, m.Serialize, this.testnet)
                        | Version m -> NetworkEnvelope.Create(VersionMessage.Command, m.Serialize, this.testnet)
                        | Ping m -> NetworkEnvelope.Create(PingMessage.Command, m.Serialize, this.testnet)
                        | Pong m -> NetworkEnvelope.Create(PongMessage.Command, m.Serialize, this.testnet)
                        | GetHeaders m -> NetworkEnvelope.Create(GetHeadersMessage.Command, m.Serialize, this.testnet)
                        | Headers m -> NetworkEnvelope.Create(GetHeadersMessage.Command, [||], this.testnet)
        if this.logging then
            printfn $"sending {envelope}"
        this.stream.Write envelope.Serialize

    member this.Read: NetworkEnvelope =
        let envelope = NetworkEnvelope.Parse(this.stream, this.testnet)
        if this.logging then
            printfn $"receiving {envelope}"
        envelope

    member this.WaitFor (messages: byte array list) =
        let mutable found = false
        let mutable command = VerAckMessage.Command
        let mutable envelope = NetworkEnvelope.Create(command, [||], this.testnet)
        while not found do
            envelope <- this.Read
            command <- envelope.command
            if command = VersionMessage.Command then
                this.Send <| VerAck VerAckMessage.Create
            else if command = PingMessage.Command then
                this.Send <| Pong (PongMessage.Create envelope.Payload)
            if List.exists (fun x -> x = envelope.command) messages then
                found <- true
        use stream = new MemoryStream(envelope.Payload)
        if command = PingMessage.Command then
            Ping (PingMessage.Parse stream)
        else if command = PongMessage.Command then
            Pong (PongMessage.Parse stream)
        else if command = VersionMessage.Command then
            Version (VersionMessage.Parse stream)
        else if command = VerAckMessage.Command then
            VerAck (VerAckMessage.Parse stream)
        else
            Headers (HeadersMessage.Parse stream)

    member this.Handshake =
        let version = VersionMessage.Create ()
        this.Send (Version version)
        this.WaitFor [VerAckMessage.Command]

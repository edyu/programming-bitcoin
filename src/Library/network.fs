module network

open System
open System.Text
open System.IO
open System.Net

let NETWORK_MAGIC = [| 0xf9uy; 0xbeuy; 0xb4uy; 0xd9uy |]
let TESTNET_NETWORK_MAGIC = [| 0x0buy; 0x11uy; 0x09uy; 0x07uy |]

type Address = IP of IPAddress | Raw of byte[]

type NetworkEnvelope = { command: byte[]; payload: byte[]; testnet: bool } with
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
                                nonce: byte[]; user_agent: string; latest_block: uint32; relay: bool } with
    member this.Command = Encoding.ASCII.GetBytes "version"
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
    static member Create(?timestamp0: uint64 option, ?nonce0: byte[] option, ?user_agent0: string,
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
        let user_agent = defaultArg user_agent0 ""
        let latest_block = defaultArg latest_block0 0u
        let relay = defaultArg relay0 false
        { version = version; services = services; timestamp = timestamp; receiver_services = receiver_services; receiver_address = receiver_address; receiver_port = receiver_port; sender_services = sender_services; sender_address = sender_address; sender_port = sender_port; nonce = nonce; user_agent = user_agent; latest_block = latest_block; relay = relay }

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
        let ua_bytes = Encoding.ASCII.GetBytes this.user_agent
        let user_agent = Array.concat [ helper.encode_varint <| uint64 ua_bytes.Length; ua_bytes ]
        let latest_block = helper.int_to_little_endian(uint64 this.latest_block, 4)
        let relay = if this.relay then [| 0x01uy |] else [| 0x00uy |]
        Array.concat [ version; services; timestamp;
                        receiver_services; receiver_address; receiver_port;
                        sender_services; sender_address; sender_port;
                        nonce; user_agent; latest_block; relay ]

type VerAckMessage = private { body: byte[] } with
    member this.Command = Encoding.ASCII.GetBytes "verack"
    member this.Body = this.body

    static member Create =
        { body = [||] }

    static member Parse = 
        VerAckMessage.Create

    member this.Serialize = this.body

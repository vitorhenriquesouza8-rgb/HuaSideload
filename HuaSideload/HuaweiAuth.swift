import CommonCrypto
import CryptoKit
import Foundation

// Pairing (HiChain) and encryption.
// Ported from Gadgetbridge: HuaweiCrypto.java, CryptoUtils.java, GetHiChainRequest.java,
// packets/DeviceConfig.java (SecurityNegotiation, PinCode, HiChain), packets/Notifications.java

enum HuaweiAuthError: Error, CustomStringConvertible {
    case crypto(String)
    case unexpected(String)
    case watchError(String)
    case tokenMismatch(String)

    var description: String {
        switch self {
        case .crypto(let s): return L("Encryption error: \(s)", "Şifreleme hatası: \(s)")
        case .unexpected(let s): return L("Unexpected reply: \(s)", "Beklenmeyen cevap: \(s)")
        case .watchError(let s): return L("The watch returned an error: \(s)", "Saat hata döndü: \(s)")
        case .tokenMismatch(let s): return L("Verification failed: \(s)", "Doğrulama tutmadı: \(s)")
        }
    }
}

enum HCrypto {
    static func random(_ count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return bytes
    }

    static func sha256(_ data: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: data))
    }

    static func hmac(key: [UInt8], _ message: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    static func hkdf(_ inputKey: [UInt8], salt: [UInt8], info: String, count: Int) -> [UInt8] {
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: inputKey), salt: salt,
                                         info: Array(info.utf8), outputByteCount: count)
        return key.withUnsafeBytes { Array($0) }
    }

    // Java AES/GCM/NoPadding: the 16-byte tag is appended to the ciphertext
    static func gcmSeal(_ plain: [UInt8], key: [UInt8], nonce: [UInt8], aad: [UInt8] = []) throws -> [UInt8] {
        do {
            let box = try AES.GCM.seal(plain, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: nonce), authenticating: aad)
            return Array(box.ciphertext) + Array(box.tag)
        } catch {
            throw HuaweiAuthError.crypto("GCM seal: \(error)")
        }
    }

    static func gcmOpen(_ data: [UInt8], key: [UInt8], nonce: [UInt8], aad: [UInt8] = []) throws -> [UInt8] {
        guard data.count >= 16 else { throw HuaweiAuthError.crypto("GCM data too short") }
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: data.dropLast(16), tag: data.suffix(16))
            return Array(try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad))
        } catch {
            throw HuaweiAuthError.crypto("GCM open: \(error)")
        }
    }

    // Java AES/CBC/PKCS5Padding
    static func cbcEncrypt(_ data: [UInt8], key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        try cbc(CCOperation(kCCEncrypt), data, key: key, iv: iv)
    }

    static func cbcDecrypt(_ data: [UInt8], key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        try cbc(CCOperation(kCCDecrypt), data, key: key, iv: iv)
    }

    private static func cbc(_ operation: CCOperation, _ data: [UInt8], key: [UInt8], iv: [UInt8]) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
        var outLength = 0
        let status = CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                             key, key.count, iv, data, data.count, &out, out.count, &outLength)
        guard status == kCCSuccess else { throw HuaweiAuthError.crypto("CBC durum kodu \(status)") }
        return Array(out.prefix(outLength))
    }
}

// Ordered JSON: Android's org.json writes keys in insertion order, so we do the same
indirect enum OrderedJSON {
    case string(String)
    case int(Int)
    case bool(Bool)
    case object([(String, OrderedJSON)])

    var text: String {
        switch self {
        case .string(let s): return "\"" + Self.escape(s) + "\""
        case .int(let i): return String(i)
        case .bool(let b): return b ? "true" : "false"
        case .object(let items): return "{" + items.map { "\"\(Self.escape($0.0))\":\($0.1.text)" }.joined(separator: ",") + "}"
        }
    }

    private static func escape(_ s: String) -> String {
        var out = ""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "/": out += "\\/"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out
    }
}

struct LinkInfo {
    var protocolVersion = 0
    var sliceSize = 0xF4
    var mtu = 0x14
    var authVersion = 0
    var deviceSupportType = 0
    var authAlgo = 0
    var bondState = 0
    var encryptMethod = 0

    init(_ tlv: HuaweiTLV) {
        if let v = tlv.int(0x01) { protocolVersion = v }
        if let v = tlv.int(0x02) { sliceSize = v }
        if let v = tlv.int(0x03) { mtu = v }
        if let v = tlv.value(0x05), v.count >= 2 { authVersion = Int(v[1]) }
        if let v = tlv.int(0x07) { deviceSupportType = v }
        if let v = tlv.int(0x08) { authAlgo = v }
        if let v = tlv.int(0x09) { bondState = v }
        if let v = tlv.int(0x0C) { encryptMethod = v }
    }

    // HuaweiTLV.encryptRaw: GCM when encryptMethod is 1 or the support type is 4
    var usesGCM: Bool { encryptMethod == 1 || deviceSupportType == 4 }
}

// DeviceConfig.SecurityNegotiation (0x01/0x33)
enum SecurityNegotiation {
    static let commandId: UInt8 = 0x33

    static func request(authMode: UInt8, deviceId: [UInt8], phoneModel: String, encryptMethod: Int) -> HuaweiTLV {
        var tlv = HuaweiTLV().with(0x01, [authMode])
        if authMode == 0x02 || authMode == 0x04 {
            tlv = tlv.with(0x02, [0x01])
        }
        tlv = tlv.with(0x05, deviceId).with(0x03, [0x01]).with(0x04, [0x00])
        if authMode == 0x04 {
            tlv = tlv.with(0x06).with(0x07, Array(phoneModel.utf8))
        }
        if encryptMethod == 1 {
            tlv = tlv.with(0x0D, [0x01])
        }
        return tlv
    }

    static func authType(_ tlv: HuaweiTLV) -> Int {
        var authType = -1
        var pw = -1
        if let b = tlv.value(0x01)?.first {
            if b == 0x01 { authType = 0x186A0 }
            if b == 0x04 { pw = 4 }
        }
        if let b = tlv.value(0x02)?.first {
            authType = Int(Int8(bitPattern: b))
            if pw != -1 { authType ^= pw }
        }
        if let b = tlv.value(0x7F)?.first {
            authType = Int(Int8(bitPattern: b))
        }
        return authType
    }

    // GetSecurityNegotiationRequest -> HiChain (0x186A0 or HiChain3) / HiChain Lite (1, 2)
    static func isHiChain(_ authType: Int) -> Bool {
        authType == 0x186A0 || (authType ^ 0x01) == 0x04 || (authType ^ 0x02) == 0x04
    }
}

// DeviceConfig.PinCode (0x01/0x2C)
enum PinCode {
    static let commandId: UInt8 = 0x2C

    private static let digestSecretV1: [UInt8] = [0x70, 0xFB, 0x6C, 0x24, 0x03, 0x5F, 0xDB, 0x55, 0x2F, 0x38, 0x89, 0x8A, 0xEE, 0xDE, 0x3F, 0x69]
    private static let digestSecretV2: [UInt8] = [0x93, 0xAC, 0xDE, 0xF7, 0x6A, 0xCB, 0x09, 0x85, 0x7D, 0xBF, 0xE5, 0x26, 0x1A, 0xAB, 0xCD, 0x78]
    private static let digestSecretV3: [UInt8] = [0x9C, 0x27, 0x63, 0xA9, 0xCC, 0xE1, 0x34, 0x76, 0x6D, 0xE3, 0xFF, 0x61, 0x18, 0x20, 0x05, 0x53]

    static func digestSecret(authVersion: Int) -> [UInt8] {
        switch authVersion {
        case 1, 4: return digestSecretV1
        case 2: return digestSecretV2
        default: return digestSecretV3
        }
    }

    static func decrypt(_ tlv: HuaweiTLV, link: LinkInfo) throws -> [UInt8] {
        guard let message = tlv.value(0x01), let iv = tlv.value(0x02) else {
            throw HuaweiAuthError.unexpected("PIN reply has no 0x01/0x02")
        }
        let key = digestSecret(authVersion: link.authVersion)
        if link.encryptMethod == 1 {
            return try HCrypto.gcmOpen(message, key: key, nonce: iv)
        }
        return try HCrypto.cbcDecrypt(message, key: key, iv: iv)
    }
}

// DeviceConfig.HiChain (0x01/0x28): 4-step handshake carrying JSON
struct HiChainMessage {
    static let commandId: UInt8 = 0x28
    static let groupId = "7B0BC0CBCE474F6C238D9661C63400B797B166EA7849B3A370FC73A9A236E989"

    let operationCode: UInt8   // 1 = authenticate (with the PIN), 2 = bind (with the saved key)
    let requestId: UInt64
    let selfAuthId: [UInt8]

    func stepOne(isoSalt: [UInt8], seed: [UInt8]) -> HuaweiTLV {
        var payload: [(String, OrderedJSON)] = [
            ("isoSalt", .string(isoSalt.hexCompact)),
            ("peerAuthId", .string(selfAuthId.hexCompact)),
            ("operationCode", .int(Int(operationCode))),
            ("seed", .string(seed.hexCompact)),
            ("peerUserType", .int(0)),
        ]
        if operationCode == 2 {
            payload += [
                ("pkgName", .string("com.huawei.devicegroupmanage")),
                ("serviceType", .string(Self.groupId)),
                ("keyLength", .int(0x20)),
            ]
        }
        return tlv(message: 1, payload: payload, deviceLevel: operationCode == 2)
    }

    func stepTwo(token: [UInt8]) -> HuaweiTLV {
        tlv(message: 2, payload: [
            ("peerAuthId", .string(selfAuthId.hexCompact)),
            ("token", .string(token.hexCompact)),
        ], deviceLevel: operationCode == 2)
    }

    func stepThree(nonce: [UInt8], encData: [UInt8]) -> HuaweiTLV {
        tlv(message: 3, payload: [
            ("nonce", .string(nonce.hexCompact)),
            ("encData", .string(encData.hexCompact)),
        ], deviceLevel: false)
    }

    // Binding (op 2) skips step 3 but the message number stays 3 (GetHiChainRequest.createRequest)
    func stepFour(nonce: [UInt8], encResult: [UInt8]) -> HuaweiTLV {
        tlv(message: operationCode == 1 ? 4 : 3, payload: [
            ("nonce", .string(nonce.hexCompact)),
            ("encResult", .string(encResult.hexCompact)),
            ("operationCode", .int(Int(operationCode))),
        ], deviceLevel: false)
    }

    private func tlv(message: Int, payload: [(String, OrderedJSON)], deviceLevel: Bool) -> HuaweiTLV {
        let version: OrderedJSON = .object([("minVersion", .string("1.0.0")), ("currentVersion", .string("2.0.16"))])
        var value: [(String, OrderedJSON)] = [
            ("authForm", .int(0)),
            ("payload", .object([("version", version)] + payload)),
            ("groupAndModuleVersion", .string("2.0.1")),
            ("message", .int(operationCode == 2 ? message | 0x10 : message)),
        ]
        if operationCode == 1 {
            let deviceId = String(decoding: selfAuthId, as: UTF8.self)
            value += [
                ("requestId", .string(String(requestId))),
                ("groupId", .string(Self.groupId)),
                ("groupName", .string("health_group_name")),
                ("groupOp", .int(2)),
                ("groupType", .int(256)),
                ("peerDeviceId", .string(deviceId)),
                ("connDeviceId", .string(deviceId)),
                ("appId", .string("com.huawei.health")),
                ("ownerName", .string("")),
            ]
        }
        if deviceLevel {
            value.append(("isDeviceLevel", .bool(false)))
        }
        return HuaweiTLV()
            .with(0x01, Array(OrderedJSON.object(value).text.utf8))
            .with(0x02, [operationCode])
            .with(0x03, .bigEndian(requestId))
    }

    enum Response {
        case step(Int, [String: Any])
        case finished
    }

    // DeviceConfig.HiChain.Response.parseTlv (Huawei framing: 0x04 = type, 0x01 = JSON)
    static func parseResponse(_ tlv: HuaweiTLV) throws -> Response {
        if let code = tlv.int(0x7F), code != HuaweiPacket.resultSuccess {
            throw HuaweiAuthError.watchError(String(format: "HiChain result 0x%X", code))
        }
        guard let type = tlv.value(0x04)?.first else {
            throw HuaweiAuthError.unexpected("HiChain reply has no type (0x04): \(tlv.description)")
        }
        guard type == 0x00 else { return .finished }

        guard let raw = tlv.value(0x01) else {
            throw HuaweiAuthError.unexpected("HiChain reply has no JSON (0x01), tags: \(tagList(tlv))")
        }
        guard let value = lenientJSONObject(raw) else {
            throw HuaweiAuthError.unexpected("HiChain JSON could not be decoded (\(raw.count) bytes, tags: \(tagList(tlv)), "
                + "starts \(Array(raw.prefix(16)).hexCompact), ends \(Array(raw.suffix(16)).hexCompact))")
        }
        // org.json (Gadgetbridge) also accepts a payload that arrives as an embedded JSON string
        let payloadField = value["payload"]
        guard let payload = payloadField as? [String: Any]
                ?? (payloadField as? String).flatMap({ lenientJSONObject(Array($0.utf8)) }) else {
            throw HuaweiAuthError.unexpected("HiChain JSON has no payload object, keys: "
                + value.keys.sorted().joined(separator: ","))
        }
        if let code = payload["errorCode"] as? Int, code != 0 {
            throw HuaweiAuthError.watchError("HiChain errorCode \(code)")
        }
        if payload["isoSalt"] != nil { return .step(1, payload) }
        if payload["returnCodeMac"] != nil { return .step(2, payload) }
        if payload["encAuthToken"] != nil { return .step(3, payload) }
        return .step(0, payload)
    }

    // JSONSerialization is stricter than Gadgetbridge's org.json: it rejects trailing NUL bytes,
    // whitespace or other bytes after the closing brace. Retry on the outermost {...} span.
    private static func lenientJSONObject(_ raw: [UInt8]) -> [String: Any]? {
        if let object = try? JSONSerialization.jsonObject(with: Data(raw)) as? [String: Any] { return object }
        guard let start = raw.firstIndex(of: UInt8(ascii: "{")),
              let end = raw.lastIndex(of: UInt8(ascii: "}")), start < end else { return nil }
        return try? JSONSerialization.jsonObject(with: Data(raw[start...end]), options: [.fragmentsAllowed]) as? [String: Any]
    }

    private static func tagList(_ tlv: HuaweiTLV) -> String {
        tlv.items.map { String(format: "%02X(%d)", $0.tag, $0.value.count) }.joined(separator: " ")
    }

    static func hexField(_ payload: [String: Any], _ key: String) throws -> [UInt8] {
        guard let s = payload[key] as? String, let bytes = [UInt8](hex: s) else {
            throw HuaweiAuthError.unexpected("JSON field missing: \(key)")
        }
        return bytes
    }
}

// DeviceConfig.ProductInfo (0x01/0x07)
enum ProductInfo {
    static let commandId: UInt8 = 0x07

    static func request() -> HuaweiTLV {
        [0x01, 0x02, 0x07, 0x09, 0x0A, 0x11, 0x12, 0x16, 0x1A, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23]
            .reduce(HuaweiTLV()) { $0.with($1) }
    }

    static var serialPrefix: String { L("Serial number: ", "Seri no: ") }

    static func describe(_ tlv: HuaweiTLV) -> [String] {
        func text(_ tag: UInt8) -> String? {
            guard let v = tlv.value(tag), !v.isEmpty else { return nil }
            return String(decoding: v, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines.union(.controlCharacters))
        }
        var lines: [String] = []
        if let s = text(0x0A) { lines.append("Model: \(s)") }
        if let s = text(0x11) { lines.append(L("Device name: ", "Cihaz adı: ") + s) }
        if let s = text(0x07) { lines.append(L("Firmware: ", "Yazılım sürümü: ") + s) }
        if let s = text(0x03) { lines.append(L("Hardware: ", "Donanım sürümü: ") + s) }
        if let s = text(0x09) { lines.append(serialPrefix + s) }
        return lines
    }
}

// Notifications.NotificationActionRequest (0x02/0x01)
enum WatchNotification {
    static let serviceId: UInt8 = 0x02
    static let commandId: UInt8 = 0x01

    private static let textTypeText: UInt8 = 0x01
    private static let textTypeSender: UInt8 = 0x02
    private static let textTypeTitle: UInt8 = 0x03
    private static let typeSms: UInt8 = 0x02
    private static let contentFormat: UInt8 = 0x02   // Gadgetbridge: "Always 0x02"

    static func request(id: UInt16, title: String, sender: String, text: String) -> HuaweiTLV {
        let elements = [(textTypeTitle, title), (textTypeSender, sender), (textTypeText, text)].map { type, value -> [UInt8] in
            var element = HuaweiTLV().with(0x0E, [type]).with(0x0F, [contentFormat])
            if !value.isEmpty { element = element.with(0x10, Array(value.utf8)) }
            return element.serialize()
        }
        let list = elements.reduce(HuaweiTLV()) { $0.with(0x8D, $1) }
        return HuaweiTLV()
            .with(0x01, .bigEndian(id))
            .with(0x02, [typeSms])
            .with(0x03, [0x01])
            .with(0x84, HuaweiTLV().with(0x8C, list.serialize()).serialize())
    }
}

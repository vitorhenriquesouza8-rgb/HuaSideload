import Foundation

// Ported from Gadgetbridge: packets/MusicControl.java, packets/DeviceConfig.java (SupportedServices)

// The watch's music screen: the phone sends the song info, the watch sends button presses
enum MusicControl {
    static let serviceId: UInt8 = 0x25
    static let statusCommand: UInt8 = 0x01   // watch -> phone: music screen opened, wants info
    static let infoCommand: UInt8 = 0x02     // phone -> watch: artist, title, state, volume
    static let controlCommand: UInt8 = 0x03  // watch -> phone: button / volume

    enum Button: UInt8 {
        case play = 1, pause, previous, next, volumeUp, volumeDown

        var name: String {
            switch self {
            case .play: return "▶ oynat"
            case .pause: return "⏸ duraklat"
            case .previous: return "⏮ geri"
            case .next: return "⏭ ileri"
            case .volumeUp: return "ses +"
            case .volumeDown: return "ses −"
            }
        }
    }

    // The watch truncates long text anyway; keep the packet small
    private static func clip(_ s: String) -> [UInt8] {
        Array(String(s.prefix(90)).utf8)
    }

    // playState uses Android PlaybackState values: 2 = paused, 3 = playing
    static func info(artist: String, title: String, playing: Bool, volume: UInt8, maxVolume: UInt8) -> HuaweiTLV {
        HuaweiTLV()
            .with(0x01, clip(artist))
            .with(0x02, clip(title))
            .with(0x03, [playing ? 3 : 2])
            .with(0x04, [maxVolume])
            .with(0x05, [volume])
    }

    static func ack() -> HuaweiTLV {
        HuaweiTLV().with(0x7F, .bigEndian(UInt32(HuaweiPacket.resultSuccess)))
    }

    // The watch's own music player (HuaweiMusicManager): the file is uploaded over 0x28 as type "music",
    // then the watch asks for its title and artist with 0x09
    static let storageCommand: UInt8 = 0x04
    static let uploadInfoCommand: UInt8 = 0x09
    static let fileType: UInt8 = 2
    static let formats = ["mp3", "wav", "aac", "m4a", "flac", "opus"]

    static func uploadInfoReply(index: Int, title: String, artist: String) -> HuaweiTLV {
        HuaweiTLV().with(0x01, .bigEndian(UInt16(truncatingIfNeeded: index)))
            .with(0x03, Array(String(title.prefix(80)).utf8))
            .with(0x04, Array(String(artist.prefix(60)).utf8))
    }

    struct Storage {
        let freeMB: Int
        let maxSongs: Int
        let songs: Int
    }

    static func storage(_ tlv: HuaweiTLV) -> Storage {
        Storage(freeMB: tlv.int(0x02) ?? 0, maxSongs: tlv.int(0x04) ?? 0, songs: tlv.int(0x05) ?? 0)
    }
}

// Asks which of the known services the watch supports (DeviceConfig 0x02)
enum SupportedServices {
    static let commandId: UInt8 = 0x02

    static let known: [UInt8] = [
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1D, 0x20,
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2A, 0x2B, 0x2D, 0x2E,
        0x30, 0x32, 0x33, 0x34, 0x35,
    ]

    static func request() -> HuaweiTLV {
        HuaweiTLV().with(0x01, known)
    }

    static func supported(_ tlv: HuaweiTLV) -> [UInt8] {
        guard let flags = tlv.value(0x02) else { return [] }
        return zip(known, flags).filter { $0.1 == 1 }.map(\.0)
    }
}

// Uploading files to the watch (apps, watch faces, music). Gadgetbridge: packets/FileUpload.java, HuaweiUploadManager.java
// The watch drives the flow: the phone sends the file info, then the watch asks for the hash, parameters and chunks.
enum FileUpload {
    static let serviceId: UInt8 = 0x28

    enum Command {
        static let info: UInt8 = 0x02          // phone -> watch: name, size, type
        static let hash: UInt8 = 0x03          // watch asks for the hash, phone sends SHA-256
        static let consult: UInt8 = 0x04       // watch announces parameters, phone acknowledges
        static let chunkParams: UInt8 = 0x05   // watch: "send this many bytes from this offset"
        static let chunk: UInt8 = 0x06         // phone -> watch: data chunk
        static let result: UInt8 = 0x07        // watch: done, phone confirms
        static let deviceError: UInt8 = 0x08   // watch: error code
    }

    enum FileType {
        static let watchface: UInt8 = 1
        static let app: UInt8 = 6
    }

    static let success = 100000

    static func info(fileName: String, size: Int, type: UInt8) -> HuaweiTLV {
        HuaweiTLV()
            .with(0x01, Array(fileName.utf8))
            .with(0x02, .bigEndian(UInt32(size)))
            .with(0x03, [type])
    }

    static func hash(fileId: UInt8, sha256: [UInt8]) -> HuaweiTLV {
        HuaweiTLV().with(0x01, [fileId]).with(0x03, sha256)
    }

    static func consultAck(fileId: UInt8, noEncrypt: Bool) -> HuaweiTLV {
        var tlv = HuaweiTLV().with(0x7F, .bigEndian(UInt32(success))).with(0x01, [fileId])
        if noEncrypt { tlv = tlv.with(0x09, [0x01]) }
        return tlv
    }

    static func complete(fileId: UInt8) -> HuaweiTLV {
        HuaweiTLV().with(0x7F, .bigEndian(UInt32(success))).with(0x01, [fileId])
    }

    // HuaweiPacket.serializeFileChunk: every unit = [file id][index][offset BE32] + data
    static func chunkPayloads(_ data: ArraySlice<UInt8>, offset: Int, unitSize: Int, fileId: UInt8) -> [[UInt8]] {
        var payloads: [[UInt8]] = []
        var position = data.startIndex
        var sliceStart = offset
        var index: UInt8 = 0
        while position < data.endIndex {
            let end = min(position + max(unitSize, 1), data.endIndex)
            payloads.append([fileId, index] + .bigEndian(UInt32(sliceStart)) + data[position..<end])
            sliceStart += end - position
            position = end
            index &+= 1
        }
        return payloads
    }

    static func describe(error code: Int) -> String {
        switch code {
        case 140004: return L("too many watch faces/files on the watch", "saatte çok fazla kadran/dosya var")
        case 140008: return L("this file is already on the watch", "bu dosya saatte zaten var")
        case 140009: return L("no space left on the watch", "saatte yer yok")
        default: return L("watch error code \(code)", "saat hata kodu \(code)")
        }
    }
}

// Apps on the watch (Gadgetbridge: packets/App.java)
enum WatchApps {
    static let serviceId: UInt8 = 0x2A
    static let installStatusCommand: UInt8 = 0x02   // watch -> phone: install progress/result
    static let deleteCommand: UInt8 = 0x01
    static let listCommand: UInt8 = 0x03
    static let paramsCommand: UInt8 = 0x06

    // App.AppDelete: 0x01=1, 0x02=package name
    static func delete(package: String) -> HuaweiTLV {
        HuaweiTLV().with(0x01, [0x01]).with(0x02, Array(package.utf8))
    }

    struct Installed: Identifiable {
        var id: String { package }
        let package: String
        let name: String
        let version: String
    }

    // Inside the 0x81 container every app/parameter group is a 0x82
    private static func groups(_ tlv: HuaweiTLV) -> [HuaweiTLV] {
        guard let outer = tlv.value(0x81), let container = try? HuaweiTLV.parse(outer) else { return [] }
        return container.items.filter { $0.tag == 0x82 }.compactMap { try? HuaweiTLV.parse($0.value) }
    }

    private static func text(_ tlv: HuaweiTLV, _ tag: UInt8) -> String {
        tlv.value(tag).map { String(decoding: $0, as: UTF8.self) } ?? ""
    }

    static func describeParams(_ tlv: HuaweiTLV) -> String {
        guard let p = groups(tlv).first else { return "no parameters (\(tlv.description))" }
        var parts = ["type \(p.int(0x03) ?? -1)\((p.int(0x03) == 38) ? " (lite wearable)" : "")",
                     "API \(p.int(0x04) ?? -1)",
                     "OS \(text(p, 0x05))"]
        if p.value(0x06) != nil { parts.append("screen \(text(p, 0x06))") }
        if let w = p.int(0x07), let h = p.int(0x08) { parts.append("\(w)x\(h)") }
        if let level = p.int(0x09) { parts.append("build \(level) \(text(p, 0x0A))") }
        return parts.joined(separator: ", ")
    }

    static func apiLevel(_ tlv: HuaweiTLV) -> Int? {
        groups(tlv).first?.int(0x04)
    }

    static func installed(_ tlv: HuaweiTLV) -> [Installed] {
        groups(tlv).map { Installed(package: text($0, 0x03), name: text($0, 0x06), version: text($0, 0x04)) }
    }

    // AppInstallStatus: 0-100 percent, 101 started, 102 installed, 103 failed, 104-106 removal
    static func describeStatus(_ status: Int) -> String {
        switch status {
        case 0...100: return L("installing \(status)%", "kuruluyor %\(status)")
        case 101: return L("install started", "kurulum başladı")
        case 102: return L("INSTALLED", "KURULDU")
        case 103: return L("install FAILED", "kurulum BAŞARISIZ")
        case 104: return L("removal started", "kaldırma başladı")
        case 105: return L("removed", "kaldırıldı")
        case 106: return L("removal failed", "kaldırma başarısız")
        default: return L("unknown status \(status)", "bilinmeyen durum \(status)")
        }
    }
}

// Messaging between the phone and apps on the watch (Gadgetbridge: packets/P2P.java, p2p/HuaweiBaseP2PService.java)
enum P2P {
    static let serviceId: UInt8 = 0x34
    static let commandId: UInt8 = 0x01

    enum Kind {
        static let ping: UInt8 = 1
        static let data: UInt8 = 2
        static let ack: UInt8 = 3
    }

    // Acknowledgement codes (Wear Engine): 0xCF = received, 0xCD = ping reply (app present), 0xCE = app not running
    enum Code {
        static let ok = 0xCF
        static let pingReply = 0xCD
    }

    struct Message {
        let kind: UInt8
        let sequence: UInt16
        let source: String
        let destination: String
        let data: [UInt8]?
        let code: Int?
    }

    static func request(kind: UInt8, sequence: UInt16, source: String, destination: String,
                        sourceFingerprint: String? = nil, destinationFingerprint: String? = nil,
                        data: [UInt8]? = nil, code: Int = 0) -> HuaweiTLV {
        var tlv = HuaweiTLV()
            .with(0x01, [kind])
            .with(0x02, .bigEndian(sequence))
            .with(0x03, Array(source.utf8))
            .with(0x04, Array(destination.utf8))
        if kind == Kind.data {
            if let sourceFingerprint { tlv = tlv.with(0x05, Array(sourceFingerprint.utf8)) }
            if let destinationFingerprint { tlv = tlv.with(0x06, Array(destinationFingerprint.utf8)) }
        }
        if let data, !data.isEmpty { tlv = tlv.with(0x07, data) }
        if kind == Kind.ack { tlv = tlv.with(0x08, .bigEndian(UInt32(truncatingIfNeeded: code))) }
        return tlv
    }

    static func parse(_ tlv: HuaweiTLV) -> Message? {
        guard let kind = tlv.value(0x01)?.first, let sequence = tlv.int(0x02) else { return nil }
        func text(_ tag: UInt8) -> String { tlv.value(tag).map { String(decoding: $0, as: UTF8.self) } ?? "" }
        return Message(kind: kind, sequence: UInt16(truncatingIfNeeded: sequence), source: text(0x03), destination: text(0x04),
                       data: tlv.value(0x07), code: tlv.int(0x08))
    }
}

// The watch asking "who is the phone?" (DeviceConfig.PhoneInfo 0x01/0x10). The watch sends the tags it wants;
// like Gadgetbridge we answer as Android 14 + Huawei Health 16.1.3.320.
enum PhoneInfo {
    static let commandId: UInt8 = 0x10
    static let phoneModel = "SM-S918B"

    // A packet holding only 0x7F=success is the watch's acknowledgement and needs no reply
    static func requestedTags(_ tlv: HuaweiTLV) -> [UInt8]? {
        if tlv.items.count == 1, tlv.int(0x7F) == HuaweiPacket.resultSuccess { return nil }
        return tlv.items.map(\.tag)
    }

    static func answer(_ tags: [UInt8]) -> HuaweiTLV {
        var tlv = HuaweiTLV()
        for tag in tags {
            switch tag {
            case 0x00, 0x0F: break
            case 0x02, 0x04, 0x15: tlv = tlv.with(tag)                       // manufacturer, model, OS platform version: empty
            case 0x08: tlv = tlv.with(tag, Array("14".utf8))                 // Android version
            case 0x11: tlv = tlv.with(tag, .bigEndian(UInt32(1_600_103_320))) // Huawei Health 16.1.3.320
            default: tlv = tlv.with(tag, [0x00])
            }
        }
        return tlv
    }
}

// Requests Gadgetbridge sends right after authentication (DeviceConfig.TimeRequest, AcceptAgreement,
// PermissionCheck; AccountRelated.SendExtendedAccountToDevice)
enum PhoneSetup {
    static let timeCommand: UInt8 = 0x05
    static let acceptAgreementCommand: UInt8 = 0x30
    static let permissionCheckCommand: UInt8 = 0x38
    static let accountServiceId: UInt8 = 0x1A
    static let extendedAccountCommand: UInt8 = 0x05

    // HuaweiUtil.getTimeAndZoneId: seconds since 1970 and the UTC offset as [hours (+128 if negative), minutes]
    static func time(_ now: Date = Date(), zone: TimeZone = .current) -> HuaweiTLV {
        let offset = zone.secondsFromGMT(for: now)
        let hours = UInt8(abs(offset) / 3600) + (offset < 0 ? 128 : 0)
        let minutes = UInt8(abs(offset) / 60 % 60)
        return HuaweiTLV()
            .with(0x01, .bigEndian(UInt32(truncatingIfNeeded: Int(now.timeIntervalSince1970))))
            .with(0x02, [hours, minutes])
    }

    // The 17-digit Huawei account ID the watch is bound to; empty sends 0x00 like Gadgetbridge
    static func extendedAccount(_ account: String) -> HuaweiTLV {
        let account = account.trimmingCharacters(in: .whitespacesAndNewlines)
        return HuaweiTLV().with(0x01, account.isEmpty ? [0x00] : Array(account.utf8))
    }

    static func acceptAgreements(_ now: Date = Date()) -> HuaweiTLV {
        let timestamp = Array(String(Int(now.timeIntervalSince1970 * 1000)).utf8)
        let list = ["software_update_service_statement", "device_information_management", "user_license_agreement"]
            .reduce(HuaweiTLV()) { list, name in
                list.with(0x82, HuaweiTLV()
                    .with(0x03, Array(name.utf8))
                    .with(0x04, [0x01])
                    .with(0x05, Array("20230508-20230508-0-0".utf8))
                    .with(0x06, timestamp)
                    .serialize())
            }
        return HuaweiTLV().with(0x81, list.serialize())
    }

    static func permissionCheckReply(permission: [UInt8]) -> HuaweiTLV {
        HuaweiTLV().with(0x01, permission).with(0x02, .bigEndian(UInt16(0)))
    }
}

import Foundation
import UIKit

struct Stat {
    let name: String
    var samples: [Double] = []   // milliseconds

    var median: Double { percentile(0.5) }
    var p99: Double { percentile(0.99) }
    var max: Double { samples.max() ?? 0 }

    func percentile(_ p: Double) -> Double {
        guard !samples.isEmpty else { return 0 }
        let sorted = samples.sorted()
        let rank = Int((Double(sorted.count) * p).rounded(.up))
        return sorted[Swift.min(sorted.count - 1, Swift.max(0, rank - 1))]
    }
}

struct BenchConfig {
    var profile: Profile = .p128
    var keygens = 10
    var signatures = 50
}

struct BenchReport {
    var device = ""
    var lines: [String] = []

    var text: String { ([device] + lines).joined(separator: "\n") }
}

@inline(__always)
func timed<T>(_ body: () throws -> T) rethrows -> (T, Double) {
    let t0 = DispatchTime.now().uptimeNanoseconds
    let v = try body()
    return (v, Double(DispatchTime.now().uptimeNanoseconds - t0) / 1e6)
}

func deviceDescription() -> String {
    var sys = utsname()
    uname(&sys)
    let model = withUnsafePointer(to: &sys.machine) {
        $0.withMemoryRebound(to: CChar.self, capacity: 1) { String(cString: $0) }
    }
    let p = ProcessInfo.processInfo
    return "\(model), iOS \(p.operatingSystemVersionString), cores \(p.activeProcessorCount), low-power: \(p.isLowPowerModeEnabled)"
}

func thermal() -> String {
    switch ProcessInfo.processInfo.thermalState {
    case .nominal: return "nominal"
    case .fair: return "fair"
    case .serious: return "serious"
    case .critical: return "critical"
    @unknown default: return "?"
    }
}

/// Runs the whole protocol against the in-process server and records client-side timings.
/// Call from a background thread.
func runBenchmark(_ cfg: BenchConfig, progress: @escaping (String) -> Void) throws -> BenchReport {
    var report = BenchReport()
    report.device = deviceDescription()
    let store = KeychainStore()
    let clientId = Data("bench-client".utf8)
    let wallet = "bench-wallet"
    try? store.delete(key: "tecdsa/client-share/\(wallet)")

    progress("server setup…")
    let (server, tServer) = try timed { try BenchServer(profile: cfg.profile, serverId: Data("bench-server".utf8)) }
    let setupBytes = try server.setupBytes()
    report.lines.append(String(format: "server setup (SampleRSA/SampleDF + proofs): %.0f ms, SetupData %d B", tServer, setupBytes.count))

    progress("verifying setup…")
    let (setup, tVerify) = try timed { try ClientSetup.verify(setupBytes: setupBytes, profile: cfg.profile) }
    report.lines.append(String(format: "client: verify setup + build tables: %.0f ms   [gate ≤ 4000]", tVerify))

    var kgC2 = Stat(name: "keygen client step 2"), kgC4 = Stat(name: "keygen client step 4")
    var kgTotal = Stat(name: "keygen client total"), kgS = Stat(name: "keygen server steps")
    var size2 = 0, size3 = 0
    for i in 0..<cfg.keygens {
        progress("keygen \(i + 1)/\(cfg.keygens)…")
        let (m1, ts1) = try timed { try server.keygenMsg1(clientId: clientId) }
        let (kg, tc2) = try timed { try ClientKeygen.start(setup: setup, clientId: clientId, msg1: m1) }
        let m2 = kg.msg2()
        let (m3, ts3) = try timed { try server.keygenMsg3(msg2: m2) }
        let (_, tc4) = try timed { try kg.finish(msg3: m3, walletId: wallet, store: store) }
        kgC2.samples.append(tc2); kgC4.samples.append(tc4); kgTotal.samples.append(tc2 + tc4); kgS.samples.append(ts1 + ts3)
        size2 = m2.count; size3 = m3.count
    }
    report.lines.append(line(kgC2)); report.lines.append(line(kgC4))
    report.lines.append(line(kgTotal) + "   [gate p99 ≤ 3000]")
    report.lines.append(line(kgS) + String(format: "; KgMsg2 %d B, KgMsg3 %d B", size2, size3))

    // The last keygen's share is the one in the Keychain and the one inside the server.
    var sgC = Stat(name: "sign client step"), sgS1 = Stat(name: "sign server step 1")
    var sgS3 = Stat(name: "sign server step 3"), sgV = Stat(name: "sign client verify result")
    var sizeA = 0, sizeB = 0
    for i in 0..<cfg.signatures {
        progress("sign \(i + 1)/\(cfg.signatures)…")
        var digest = Data(count: 32)
        _ = digest.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let (m1, t1) = try timed { try server.signMsg1(digest: digest, hd: nil) }
        let (m2, tc) = try timed {
            try clientSign(setup: setup, store: store, walletId: wallet, clientId: clientId, digest: digest, msg1: m1, hd: nil)
        }
        let (m3, t3) = try timed { try server.signFinish(msg2: m2) }
        let (_, tv) = try timed {
            try clientVerifySignature(store: store, walletId: wallet, profile: cfg.profile, digest: digest, msg3: m3, hd: nil)
        }
        sgS1.samples.append(t1); sgC.samples.append(tc); sgS3.samples.append(t3); sgV.samples.append(tv)
        sizeA = m1.count; sizeB = m2.count
    }
    report.lines.append(line(sgC) + String(format: "; SignMsg2 %d B   [gate ≤ 150]", sizeB))
    report.lines.append(line(sgS1) + String(format: "; SignMsg1 %d B", sizeA))
    report.lines.append(line(sgS3))
    report.lines.append(line(sgV))
    report.lines.append("thermal state at the end: \(thermal())")
    try? store.delete(key: "tecdsa/client-share/\(wallet)")
    return report
}

private func line(_ s: Stat) -> String {
    String(format: "%@: median %.1f ms, p99 %.1f, max %.1f (n=%d)", s.name, s.median, s.p99, s.max, s.samples.count)
}

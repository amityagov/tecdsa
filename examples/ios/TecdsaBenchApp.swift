import SwiftUI

@main
struct TecdsaBenchApp: App {
    var body: some Scene {
        WindowGroup { BenchView() }
    }
}

struct BenchView: View {
    @State private var running = false
    @State private var status = "Idle"
    @State private var output = ""
    @State private var keygens = 10
    @State private var signatures = 50
    @State private var hdSignatures = 50
    @State private var profile112 = false

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 12) {
                Stepper("Keygens: \(keygens)", value: $keygens, in: 1...1000)
                Stepper("Signatures: \(signatures)", value: $signatures, in: 1...1000, step: 10)
                Stepper("HD signatures: \(hdSignatures)", value: $hdSignatures, in: 0...1000, step: 10)
                Toggle("112-bit profile", isOn: $profile112)
                Button(running ? "Running…" : "Run benchmark", action: run)
                    .buttonStyle(.borderedProminent)
                    .disabled(running)
                Text(status).font(.footnote).foregroundStyle(.secondary)
                ScrollView {
                    Text(output)
                        .font(.system(.footnote, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
                if !output.isEmpty {
                    ShareLink(item: output) { Label("Share results", systemImage: "square.and.arrow.up") }
                }
            }
            .padding(.horizontal, 16)
            .navigationTitle("tecdsa bench")
            .onAppear {
                if CommandLine.arguments.contains("-autorun"), !running {
                    // `-keygens N -signatures N` launch arguments arrive through UserDefaults.
                    let d = UserDefaults.standard
                    if d.integer(forKey: "keygens") > 0 { keygens = d.integer(forKey: "keygens") }
                    if d.integer(forKey: "signatures") > 0 { signatures = d.integer(forKey: "signatures") }
                    if d.object(forKey: "hdSignatures") != nil { hdSignatures = d.integer(forKey: "hdSignatures") }
                    runBenchmarkAsync()
                }
            }
        }
    }

    private func run() {
        runBenchmarkAsync()
    }

    /// Also started by the launch argument `-autorun` (prints the report to stdout, for `simctl launch --console`).
    private func runBenchmarkAsync() {
        running = true
        output = ""
        let cfg = BenchConfig(profile: profile112 ? .p112 : .p128, keygens: keygens, signatures: signatures, hdSignatures: hdSignatures)
        // Run off the main thread; the heavy calls are synchronous.
        Task.detached(priority: .userInitiated) {
            do {
                let report = try runBenchmark(cfg) { s in Task { @MainActor in status = s } }
                fputs("BENCH-REPORT-BEGIN\n\(report.text)\nBENCH-REPORT-END\n", stderr)
                await MainActor.run { output = report.text; status = "Done" }
            } catch {
                fputs("BENCH-REPORT-BEGIN\nError: \(error)\nBENCH-REPORT-END\n", stderr)
                await MainActor.run { output = "Error: \(error)"; status = "Failed" }
            }
            await MainActor.run { running = false }
        }
    }
}

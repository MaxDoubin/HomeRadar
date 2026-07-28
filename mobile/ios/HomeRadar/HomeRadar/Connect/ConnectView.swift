import SwiftUI

/// Full-screen connect flow shown instead of the tab bar whenever no saved
/// appliance address+token exists (see `RootView`).
///
/// Step 1: enter/discover the appliance address.
/// Step 2: enter the 6-digit pairing code (read off the household's web
/// dashboard/kiosk screen) and claim it via `POST /pair/claim`.
/// Step 3: success -- store the address+token and hand off to the tabs.
struct ConnectView: View {
    @EnvironmentObject private var session: AppSession
    @StateObject private var discovery = ApplianceDiscovery()

    private enum Step {
        case address
        case code
        case success
    }

    @State private var step: Step = .address
    @State private var address: String = ""
    @State private var code: String = ""
    @State private var errorMessage: String?
    @State private var isBusy = false

    var body: some View {
        NavigationStack {
            Group {
                switch step {
                case .address: addressStep
                case .code: codeStep
                case .success: successStep
                }
            }
            .navigationTitle("Connect to HomeRadar")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    // MARK: - Step 1: address

    private var addressStep: some View {
        Form {
            Section("Appliance Address") {
                TextField("homeradar.local:8000", text: $address)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
            }

            Section {
                Button {
                    if discovery.isBrowsing {
                        discovery.stop()
                    } else {
                        discovery.start()
                    }
                } label: {
                    Label(
                        discovery.isBrowsing ? "Stop Scanning" : "Scan for HomeRadar on this network",
                        systemImage: "wifi"
                    )
                }

                if discovery.isBrowsing && discovery.discovered.isEmpty {
                    HStack {
                        ProgressView()
                        Text("Scanning\u{2026}")
                            .foregroundStyle(.secondary)
                    }
                }

                ForEach(discovery.discovered) { candidate in
                    Button {
                        address = candidate.addressString
                        discovery.stop()
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(candidate.name).font(.headline)
                            Text(candidate.addressString)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Text("Discovery")
            } footer: {
                Text("Not every network shows results here. If nothing appears, enter the address shown on your HomeRadar dashboard directly.")
            }

            if let errorMessage {
                Section {
                    Text(errorMessage).foregroundStyle(.red)
                }
            }

            Section {
                Button("Continue") {
                    errorMessage = nil
                    discovery.stop()
                    step = .code
                }
                .disabled(address.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .onDisappear { discovery.stop() }
    }

    // MARK: - Step 2: pairing code

    private var codeStep: some View {
        Form {
            Section {
                TextField("123456", text: $code)
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
                    .onChange(of: code) { newValue in
                        code = String(newValue.filter(\.isNumber).prefix(6))
                    }
            } header: {
                Text("Pairing Code")
            } footer: {
                Text("Enter the 6-digit code shown on your HomeRadar dashboard or kiosk screen.")
            }

            if let errorMessage {
                Section {
                    Text(errorMessage).foregroundStyle(.red)
                }
            }

            Section {
                Button {
                    claimCode()
                } label: {
                    if isBusy {
                        ProgressView()
                    } else {
                        Text("Pair")
                    }
                }
                .disabled(code.count != 6 || isBusy)

                Button("Back") {
                    errorMessage = nil
                    step = .address
                }
                .disabled(isBusy)
            }
        }
    }

    // MARK: - Step 3: success

    private var successStep: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 64))
                .foregroundStyle(.green)
            Text("Paired!")
                .font(.title2.bold())
            Text("HomeRadar is ready.")
                .foregroundStyle(.secondary)
        }
        .padding()
        .task {
            session.startLiveUpdates()
        }
    }

    // MARK: - Actions

    private func claimCode() {
        isBusy = true
        errorMessage = nil
        let trimmedAddress = address.trimmingCharacters(in: .whitespacesAndNewlines)
        let pairingClient = HomeRadarClient(baseAddress: trimmedAddress, token: nil)

        Task {
            do {
                let result = try await pairingClient.pairClaim(code: code)
                session.completeConnection(address: trimmedAddress, token: result.token)
                isBusy = false
                step = .success
            } catch {
                isBusy = false
                errorMessage = "Couldn't pair: check the code and try again."
            }
        }
    }
}

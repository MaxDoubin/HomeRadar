import SwiftUI

struct SettingsView: View {
    @StateObject var viewModel: SettingsViewModel

    var body: some View {
        NavigationStack {
            Form {
                Section("Household") {
                    TextField("Household name", text: $viewModel.householdName)
                    TextField("Digest email", text: $viewModel.digestEmail)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.emailAddress)
                }

                Section("Network") {
                    Toggle("DNS Filtering Enabled", isOn: $viewModel.dnsEnabled)
                    TextField("Upstream DNS", text: $viewModel.dnsUpstream)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                Section {
                    Toggle("Alert Notifications", isOn: $viewModel.notificationsEnabled)
                        .onChange(of: viewModel.notificationsEnabled) { _ in
                            Task { await viewModel.requestNotificationAuthorizationIfNeeded() }
                        }
                } footer: {
                    Text("Notifications are local to this device and only fire while HomeRadar's live connection is open. iOS will ask you to allow notifications the first time you turn this on.")
                }

                if let statusMessage = viewModel.statusMessage {
                    Section { Text(statusMessage).foregroundStyle(.green) }
                }
                if let errorMessage = viewModel.errorMessage {
                    Section { Text(errorMessage).foregroundStyle(.red) }
                }

                Section {
                    Button("Save Changes") {
                        Task { await viewModel.save() }
                    }
                }

                Section {
                    Button("Forget This Appliance", role: .destructive) {
                        viewModel.forgetAppliance()
                    }
                }
            }
            .navigationTitle("Settings")
            .task {
                await viewModel.load()
            }
            .overlay {
                if viewModel.isLoading {
                    ProgressView()
                }
            }
        }
    }
}

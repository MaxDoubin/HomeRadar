// electron-builder afterPack hook, macOS only.
//
// CI builds with CSC_IDENTITY_AUTO_DISCOVERY=false (see .github/workflows/
// desktop.yml) so electron-builder doesn't fail hunting for a paid Apple
// Developer ID certificate that will never exist on a CI runner. That also
// skips ad-hoc signing entirely, which is fine on Intel but not on Apple
// Silicon: arm64 macOS enforces code signing much more strictly, and a
// completely unsigned .app downloaded from the internet gets Gatekeeper's
// "is damaged and can't be opened" -- a hard block, not the normal
// bypassable "unidentified developer" warning.
//
// Signing with "-" (the special ad-hoc identity) needs no Apple Developer
// account and is free on any Mac with Xcode Command Line Tools. It does not
// make this a trusted, notarized build -- Gatekeeper will still warn on
// first launch, exactly as README.md's "First launch notes" describe -- it
// just turns "damaged" back into that expected, right-click-to-open warning.
//
// This must be wired up as electron-builder's "afterPack" hook, not
// "afterSign". electron-builder only invokes "afterSign" when its own
// signing step actually ran; with CSC_IDENTITY_AUTO_DISCOVERY=false that
// step is skipped entirely (not just "no identity found"), so an afterSign
// hook here would silently never execute at all -- confirmed locally: the
// build log says `skipping "afterSign" hook as no signing occurred, perhaps
// you intended "afterPack"?`. afterPack always runs after packaging on every
// platform, so the darwin check above is what keeps this a no-op on
// Windows/Linux builds.
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

exports.default = async function afterPack(context) {
  if (context.electronPlatformName !== "darwin") return;

  const appOutDir = context.appOutDir;
  const appBundle = fs.readdirSync(appOutDir).find((name) => name.endsWith(".app"));
  if (!appBundle) {
    throw new Error(`afterPack: no .app bundle found in ${appOutDir}`);
  }
  const appPath = path.join(appOutDir, appBundle);

  execFileSync("codesign", ["--force", "--deep", "--sign", "-", appPath], { stdio: "inherit" });
  console.log(`afterPack: ad-hoc signed ${appPath}`);
};

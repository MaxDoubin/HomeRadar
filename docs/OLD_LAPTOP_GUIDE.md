# Repurposing an Old Laptop with Home Radar

Got an old laptop collecting dust? Perfect. You can turn it into a dedicated, enterprise-grade network security appliance for your home for free using Home Radar.

This guide will walk you through the entire process, from getting your laptop ready to securing your network.

## What You Need

Before you begin, gather the following:

1.  **An Old Laptop or Desktop PC**: It doesn't need to be powerful. Any 64-bit machine from the last 10-15 years should work just fine. Ideally, it has an Ethernet port.
2.  **A USB Flash Drive**: You need a USB drive with at least 8GB of storage space. **Warning: All data on this drive will be erased.**
3.  **An Ethernet Cable**: To connect the laptop directly to your router. While Wi-Fi might work in some setups, a wired connection is strongly recommended for stability and performance.
4.  **Another Computer**: A working computer (Windows, Mac, or Linux) to download the Home Radar image and flash it to the USB drive.

---

## Step 1: Download the Home Radar ISO

You'll need the Home Radar "ISO" file. An ISO is a disc image that contains the entire Home Radar operating system and software.

*   *(Note: Since this is currently in development, if a pre-built ISO is not available in the Releases section, you will need to build the ISO yourself using the instructions in `docs/INSTALL.md` under "Live ISO".)*
*   Once available, download the `homeradar-amd64.iso` file to your working computer.

---

## Step 2: Flash the ISO to Your USB Drive

You need a special tool to write the ISO to the USB drive so that the old laptop can boot from it. We recommend using **Rufus** (Windows) or **balenaEtcher** (Windows, Mac, Linux).

**Using balenaEtcher (Recommended for all platforms):**

1.  Download and install [balenaEtcher](https://etcher.balena.io/).
2.  Plug your USB flash drive into your working computer.
3.  Open balenaEtcher.
4.  Click **Flash from file** and select the `homeradar-amd64.iso` file you downloaded.
5.  Click **Select target** and choose your USB flash drive. **Double-check you selected the correct drive!**
6.  Click **Flash!**. The process will take a few minutes. Once finished, safely eject the USB drive.

---

## Step 3: Boot the Old Laptop from the USB Drive

This is often the trickiest part, as it varies depending on your laptop's manufacturer.

1.  Make sure the old laptop is turned **off**.
2.  Plug the newly flashed USB drive into the old laptop.
3.  Connect the laptop to your internet router using the **Ethernet cable**.
4.  Plug the laptop into power (so the battery doesn't die during setup).
5.  Turn the laptop on and **immediately and repeatedly** press the key to open the "Boot Menu" or "BIOS/UEFI Settings". Common keys are:
    *   **Dell**: F12 or F2
    *   **HP**: F9 or F10 or ESC
    *   **Lenovo**: F12 or F1 or F2 (or use the small "Novo" button on the side if it has one)
    *   **Asus**: F8 or ESC or F2
    *   **Acer**: F12 or F2
    *   *If you're unsure, watch the screen when it first turns on; it usually says "Press [Key] for Boot Menu". You can also search online for "boot menu key [your laptop brand]".*
6.  Once in the Boot Menu, use the arrow keys to select your USB drive (it might be named "USB Storage Device", "UEFI: [Brand name]", or similar).
7.  Press **Enter**. The laptop should now boot into the Home Radar installer or live environment.

---

## Step 4: Install Home Radar

*(Note: Specific installation steps will depend on the final ISO implementation. The Debian Live ISO built via `iso/build-iso.sh` acts as a live session or can be installed).*

Follow the on-screen instructions on the old laptop.
- If prompted, choose the option to install it to the hard drive (this will erase the old Windows/macOS/Linux on that laptop).
- Once installation is complete, it will prompt you to remove the USB drive and restart.

---

## Step 5: Access the Dashboard and Set Up Your Network

Once the laptop reboots, it is now your Home Radar appliance! The screen will likely just show a status page or remain blank, which is normal. The magic happens over your network.

1.  Go back to your main, working computer (or your smartphone). Make sure you are connected to the **same home Wi-Fi or network** as the new Home Radar appliance.
2.  Open a web browser (Chrome, Safari, etc.).
3.  You need to find the IP address of your new Home Radar laptop.
    - The easiest way is to check your router's "Connected Devices" or "DHCP Client List" page. Look for a newly connected wired device.
    - Let's say the IP address is `192.168.1.50`.
4.  In your web browser, go to: `http://<YOUR_APPLIANCE_IP>:8000` (e.g., `http://192.168.1.50:8000`).
5.  You should now see the **Home Radar Dashboard**!
6.  Follow the **First-Run Wizard** on the screen. It will guide you through:
    *   Setting a household name.
    *   Entering an email address for your weekly security digest (optional).
    *   Setting up your upstream DNS provider.

---

## Step 6: Activate Network-Wide Protection

Right now, Home Radar can see your network, but to block threats (like malware and ads), your devices need to use it for DNS.

**You have two options:**

**Option A: Test it on one device first (Recommended)**
Before changing your whole house, try it on your phone or computer.
1.  Go to the Wi-Fi/Network settings on your phone or PC.
2.  Change the DNS server from "Automatic" to "Manual" and enter the Home Radar IP address (e.g., `192.168.1.50`).
3.  Browse the web and check the Home Radar dashboard to ensure queries are being processed.

**Option B: Protect the whole house via the Router**
To protect everything automatically (Smart TVs, IoT devices, laptops):
1.  Log into your home router's admin interface.
2.  Find the **DHCP** or **LAN** settings.
3.  Look for "DNS Server" or "Primary DNS".
4.  Change it to the IP address of your Home Radar laptop (e.g., `192.168.1.50`).
5.  Save the settings.
6.  *Note: It might take a few hours for all devices in your house to pick up the new setting, or you can restart your router and devices to force the update.*

**Important:** Do not lose the Home Radar appliance IP address. You can set a static IP for it in your router's settings to ensure it never changes.

## Congratulations!
Your old laptop is now actively protecting your home network. Check the dashboard to review device trust scores, block suspicious activity, and keep your family secure.
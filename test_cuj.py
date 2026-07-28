from playwright.sync_api import sync_playwright

def run_cuj(page):
    page.goto("http://localhost:5173")
    page.wait_for_timeout(2000)

    # Click on "Settings" in the sidebar
    page.get_by_role("button", name="Settings").click()
    page.wait_for_timeout(1000)

    # Search in CISA
    page.get_by_placeholder("Search vendor, product, or CVE...").fill("apple")
    page.wait_for_timeout(500)
    page.get_by_role("button", name="Search").click()
    page.wait_for_timeout(2000)

    # Take screenshot at the key moment
    page.screenshot(path="/home/jules/verification/screenshots/verification.png")
    page.wait_for_timeout(1000)

if __name__ == "__main__":
    import os
    os.makedirs("/home/jules/verification/videos", exist_ok=True)
    os.makedirs("/home/jules/verification/screenshots", exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            record_video_dir="/home/jules/verification/videos"
        )
        page = context.new_page()
        try:
            run_cuj(page)
        finally:
            context.close()
            browser.close()

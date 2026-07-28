from playwright.sync_api import sync_playwright

def run_cuj(page):
    page.goto("http://localhost:5173")
    page.wait_for_timeout(2000)

    # Click on "Settings" in the sidebar
    page.get_by_role("button", name="Settings").click()
    page.wait_for_timeout(1000)

    # Take screenshot of settings
    page.screenshot(path="/home/jules/verification/screenshots/verification3a.png")
    page.wait_for_timeout(1000)

    # Click on "Advanced" in the sidebar
    page.get_by_role("button", name="Advanced").click()
    page.wait_for_timeout(1000)

    # Take screenshot of advanced
    page.screenshot(path="/home/jules/verification/screenshots/verification3b.png")
    page.wait_for_timeout(1000)

if __name__ == "__main__":
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

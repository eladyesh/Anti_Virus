from selenium import webdriver

# Open Chrome browser
browser = webdriver.Chrome()

# Navigate to settings page
browser.get("chrome://settings/clearBrowserData")

# Clear browser history
browser.find_element_by_xpath('//settings-ui').shadowRoot.getElementById('clearBrowsingDataConfirm').click()
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import time
import os

# Path to your existing Chrome profile
chrome_profile_path = r"C:\Users\sujal\AppData\Local\Google\Chrome\User Data"
profile_directory = "Profile 1"  # Replace with the name of your Chrome profile

# Initialize Chrome options
chrome_options = Options()

# Enable headless mode (run without GUI)
chrome_options.add_argument("--headless")

# Use the existing Chrome profile
chrome_options.add_argument(f"user-data-dir={chrome_profile_path}")  # Path to user data
chrome_options.add_argument(f"profile-directory={profile_directory}")  # The specific profile you want to load

# Set up WebDriver
driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

# Open a website to verify it's working
driver.get("https://www.google.com")

# Wait for the page to load
time.sleep(3)

# Get the title of the page
print(driver.title)  # Should print "Google"

# Close the browser
driver.quit()

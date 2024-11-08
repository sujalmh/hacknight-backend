from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from bs4 import BeautifulSoup
import time
import os
from urllib.parse import unquote, unquote_plus

chrome_profile_path = r"C:\Users\sujal\AppData\Local\Google\Chrome\User Data"
profile_directory = "Default"
chrome_options = Options()
chrome_options.add_argument(f"--headless")
chrome_options.add_argument(f"user-data-dir={chrome_profile_path}")  # Path to user data
chrome_options.add_argument(f"profile-directory={profile_directory}")  # The specific profile you want to load

# Set up WebDriver
def get_skills(profileurl):
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
    driver.get(profileurl)


    elements = driver.find_elements(By.XPATH, '//a[@data-field="skill_page_skill_topic"]')

    skills = []
    for element in elements:
        skill = element.get_attribute("href")
        skill = ''.join(skill.split('https://www.linkedin.com/search/results/all/?keywords='))
        skill = skill.replace("&origin=PROFILE_PAGE_SKILL_NAVIGATION","")
        skill = unquote(skill)
        skill = skill.replace("+"," ")
        skills.append(skill)

    driver.quit()
    return list(set(skills))

print(get_skills("https://www.linkedin.com/in/sujnankumar/details/skills/"))
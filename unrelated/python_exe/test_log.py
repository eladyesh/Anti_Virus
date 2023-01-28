import requests
from bs4 import BeautifulSoup

url = "https://www.exetools.com/"  # replace with website you want to crawl
page = requests.get(url)
soup = BeautifulSoup(page.content, 'html.parser')

# Search for UPX on the website
upx_text = soup.find_all(string='UPX')
print(upx_text)

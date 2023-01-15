from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
import re

# define the seed url
seed_url = "https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea"

# function name to search for
function_names = "CreateFileW"


def search_page(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    # search for the function name in the page
    if function_names[:-1] in soup.get_text():
        # extract the prototype of the function
        prototype = soup.find("code", text=re.compile(function_names[0]))
        if prototype:
            print(f"Prototype of {function_names[0]}: {prototype.text}")

    # find all links in the page
    links = soup.find_all('a')
    for link in links:
        link_url = link.get('href')
        # check if the link is a valid URL
        if link_url and link_url.startswith("http"):
            search_page(urljoin(seed_url, link_url))


search_page(seed_url)

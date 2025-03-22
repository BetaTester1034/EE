import requests
from datetime import datetime
import time
import pdfplumber
import os
import io
import hashlib
import google.generativeai as genai
from django.conf import settings
from app.config import GEMINI_API_KEY
import fitz

import requests
from .db import get_db

db = get_db() 

# Configure Gemini AI
genai.configure(api_key=GEMINI_API_KEY)

# Gemini AI settings
generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 8192,
}

def extract_text_from_pdf(pdf_path):
    """Extracts text from a PDF file and ignores images."""
    text = ""
    with open(pdf_path, "rb") as f:
        pdf_binary = f.read()  # Read PDF as binary

    doc = fitz.open(stream=pdf_binary, filetype="pdf")  # Open PDF from binary
    for page in doc:
        text += page.get_text("text") + "\n"  # Extract text from each page
    
    return text.strip()  # Return clean text without extra spaces


BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # App directory
PDF_PATH = os.path.join(settings.BASE_DIR, 'app', 'static', 'about_dr_fox.pdf')
pdf_text = extract_text_from_pdf(PDF_PATH)

ITEMS_TO_FEED = []
for item in list(db.items.find()):
    if item.get('item_pdf_file') is not None:
        del item['item_pdf_file']
    else:
        del item['item_video_file']
    ITEMS_TO_FEED.append(item)

model = genai.GenerativeModel(
    model_name="gemini-1.5-flash",
    generation_config=generation_config,
    system_instruction=f"""You are an AI assistant for the business website of Dr. Fox, this website is made for his students and there are products in the shop they can buy, for example: notes/past papers/videos, etc.
    Here is the entire catalog of products in the shop: {ITEMS_TO_FEED}
    Here is some info about dr. fox: {pdf_text}"""
)

# Start AI chat session
chat_session = model.start_chat(history=[])

def get_ai_response(prom: str):
    response = chat_session.send_message(prom)
    return response.text

def check_password_breach(password):
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        raise Exception("Error connecting to password breach API")

    hashes = (line.split(':') for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return True
        
    return False

def is_premium(user_id):
    user_id = str(user_id)
    premium_record = db.subscriptions.find_one({'user_id': user_id, 'status': 'Active'})
    return premium_record is not None

def get_most_bought_items(limit):
    # Get the 5 most bought items
    most_bought_items = db.purchase_history.aggregate([
        {'$group': {"_id": "$item_name", 'total_bought': {'$sum': 1}}},
        {'$sort': {'total_bought': -1}},
        {'$limit': limit}
    ])

    return most_bought_items
    
def get_subscription_data(user_id):
    user_id = str(user_id)
    subscription_record = db.subscriptions.find_one({'user_id': user_id, 'status': 'Active'})
    if subscription_record:
        return subscription_record
    else:
        return {}

def make_premium(user_id):
    user_id = str(user_id)
    # Make subscription active for 1 year
    db.subscriptions.insert_one({
        "user_id": str(user_id),
        "start_date": int(time.time()),
        "end_date": int(time.time()) + 31536000,
        "status": "Active"
    })

def get_total_sales():
    TOTAL_SALES = 0
    PURCHASE_HISTORY_COLLECTION = db.purchase_history
    all_purchases = PURCHASE_HISTORY_COLLECTION.find()
    for purchase in all_purchases:
        TOTAL_SALES += purchase["item_price"]

    return TOTAL_SALES

def is_ip_blocked(ip_addr):
    ip_record = db.ip_addresses.find_one({'address': ip_addr})
    if ip_record:
        if ip_record["is_blocked"] == 1:
            return True
        
    return False


def extract_pdf_text(pdf_binary_data):
    pdf_file = io.BytesIO(pdf_binary_data)
    with pdfplumber.open(pdf_file) as pdf:
        text = ""
        for page in pdf.pages:
            text += page.extract_text()

    return text


def get_post_replies(post_id):
    post_replies_collection = db["replies"]
    replies_cursor = post_replies_collection.find({"post_id": post_id})
    
    # Transform `_id` to `id`
    replies = []
    for reply in replies_cursor:
        reply["id"] = str(reply.pop("_id"))
        replies.append(reply)

    return replies

def get_country_data():
    url = "https://countryinfoapi.com/api/countries"
    response = requests.get(url)
    if response.status_code == 200:
        countries = response.json()
        for country in countries:
            print(country["name"])
        country_data = [
            {
                "name": country["name"]
            }
            for country in countries
        ]
        return country_data
    else:
        return []

def convert_timestamp_to_date(timestamp):
    """Converts Unix timestamp to a human-readable date."""
    # Convert the timestamp (assumed to be in seconds) to a datetime object
    return datetime.utcfromtimestamp(timestamp).strftime("%d/%m/%Y %H:%M:%S")
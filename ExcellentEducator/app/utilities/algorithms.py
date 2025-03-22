import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import httpagentparser
from app.utilities.funcs import is_premium
from collections import Counter
from app.utilities.db import get_db
from app.utilities.funcs import get_most_bought_items
import time

db = get_db()

# Track IP request patterns (Basic Rate-Limiting Storage)
REQUEST_HISTORY = {}

def bot_detection_algorithm(request):
    SUSPICIOUS_KEYWORDS = {
    'Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot', 'Baiduspider',
    'YandexBot', 'Sogou', 'Exabot', 'Facebot', 'ia_archiver',

    'requests', 'python-requests', 'python-urllib3', 'urllib',
    'python-urllib', 'scrapy', 'mechanize', 'httpx', 'aiohttp',

    'MJ12bot', 'AhrefsBot', 'SemrushBot', 'SEMrushBot',
    'DotBot', 'Bytespider', 'SerpstatBot', 'SEOkicks-Robot',

    'Nikto', 'sqlmap', 'ZAP', 'w3af', 'Acunetix', 'Nessus',
    'BurpSuite', 'Metasploit', 'nmap', 'arachni',

    'selenium', 'headless', 'PhantomJS', 'puppeteer', 'playwright',
    'curl', 'wget', 'PostmanRuntime',

    'DigitalOcean', 'Linode', 'AWS', 'GoogleCloud', 'Azure', 'OVH',
    'Cloudflare', 'fastly', 'Vultr',


    'EmailCollector', 'EmailSiphon', 'EmailWolf', 'ExtractorPro',


    'Google-Extended', 'GPTBot', 'ClaudeBot', 'ChatGPT', 'AI-ML',
    

    'bot', 'spider', 'crawler', 'fetch', 'scan', 'checker',
    'harvest', 'monitor', 'analyzer', 'extractor'
}
    
    BOT_SCORE = 0
    user_agent = request.META.get('HTTP_USER_AGENT', '')

    essential_headers = ['HTTP_USER_AGENT', 'HTTP_ACCEPT', 'HTTP_ACCEPT_LANGUAGE', 'HTTP_CONNECTION']
    missing_headers = sum(1 for header in essential_headers if header not in request.META)

    if missing_headers > 0:
        BOT_SCORE += 0.15 * missing_headers

    if not user_agent or len(user_agent) < 10:
        BOT_SCORE += 0.4

    if any(keyword in user_agent for keyword in SUSPICIOUS_KEYWORDS):
        BOT_SCORE += 0.6

    if user_agent.count('/') > 5 or 'Mozilla' not in user_agent:
        BOT_SCORE += 0.3

    parsed = httpagentparser.detect(user_agent)
    os_family = parsed.get('os', {}).get('name', '')

    if os_family == "Linux":
        BOT_SCORE += 0.2

    ip_address = request.META.get('REMOTE_ADDR', '')
    current_time = time.time()

    if ip_address:
        if ip_address in REQUEST_HISTORY:
            last_request_time, request_count = REQUEST_HISTORY[ip_address]
            time_diff = current_time - last_request_time
            
            if time_diff < 1:
                request_count += 1
            else:
                request_count = max(1, request_count * 0.9)

            REQUEST_HISTORY[ip_address] = (current_time, request_count)

            if request_count > 5:
                BOT_SCORE += 0.5
        else:
            REQUEST_HISTORY[ip_address] = (current_time, 1)

    http_method = request.method
    if http_method in ["HEAD", "OPTIONS", "TRACE"]:
        BOT_SCORE += 0.3

    referrer = request.META.get('HTTP_REFERER', '')
    if not referrer:
        BOT_SCORE += 0.1

    accept_header = request.META.get('HTTP_ACCEPT', '')
    if "image/" not in accept_header and "text/css" not in accept_header and "application/javascript" not in accept_header:
        BOT_SCORE += 0.3

    print(BOT_SCORE)

    return min(BOT_SCORE, 1)

def recommend_items(user_id, top_n=5):
    user_purchases = list(db.purchase_history.find({'user_id': user_id}))
    all_items = list(db.items.find())

    if len(all_items) <= 0:
        return []

    for i in all_items:
        if i["item_is_premium"] == "on" and not is_premium(user_id):
            all_items.remove(i)

    # If the user has no purchase history, return top most bought items
    if not user_purchases:
        return get_most_bought_items(top_n)

    # Extract item names from purchases
    user_bought_items = {purchase["item_name"] for purchase in user_purchases}

    # 1️⃣ TF-IDF Content-Based Filtering
    all_texts = [
        f"{item['item_name']} {item['item_description']} {item['item_price']}"
        for item in all_items
    ]
    user_texts = [
        f"{purchase['item_name']} {purchase['item_price']}"
        for purchase in user_purchases
    ]
    
    vectorizer = TfidfVectorizer()
    all_vectors = vectorizer.fit_transform(all_texts)
    user_vectors = vectorizer.transform(user_texts)
    
    similarities = cosine_similarity(user_vectors, all_vectors)
    avg_similarity = similarities.mean(axis=0)
    recommended_indices = np.argsort(avg_similarity)[::-1]

    # 2️⃣ Item-Based Collaborative Filtering (People who bought X also bought Y)
    all_purchase_data = list(db.purchase_history.find())
    item_to_users = {}

    for purchase in all_purchase_data:
        item_name = purchase["item_name"]
        user = purchase["user_id"]
        if item_name not in item_to_users:
            item_to_users[item_name] = set()
        item_to_users[item_name].add(user)

    # Find items bought by users who purchased similar items
    collaborative_recommendations = Counter()
    for item in user_bought_items:
        for user in item_to_users.get(item, []):
            for purchase in db.purchase_history.find({'user_id': user}):
                if purchase["item_name"] not in user_bought_items:
                    collaborative_recommendations[purchase["item_name"]] += 1

    # Sort by frequency of being bought together
    collaborative_sorted = [item for item, _ in collaborative_recommendations.most_common(top_n)]

    # 3️⃣ Blend Both Methods with Some Exploration
    recommended_items = []
    seen_items = set(user_bought_items)

    # First, add TF-IDF recommendations
    for i in recommended_indices:
        if all_items[i]["item_name"] not in seen_items:
            recommended_items.append(all_items[i])
            seen_items.add(all_items[i]["item_name"])
            if len(recommended_items) >= top_n // 2:
                break

    # Then, add Collaborative Filtering recommendations
    for item_name in collaborative_sorted:
        if item_name not in seen_items:
            item = next((p for p in all_items if p["item_name"] == item_name), None)
            if item:
                recommended_items.append(item)
                seen_items.add(item_name)
                if len(recommended_items) >= top_n:
                    break

    # 4️⃣ If Not Enough Items, Add Some Random "Exploration" Items
    if len(recommended_items) < top_n:
        random_items = [item for item in all_items if item["item_name"] not in seen_items]
        np.random.shuffle(random_items)
        recommended_items.extend(random_items[:top_n - len(recommended_items)])

    recommended_products = []

    for item in recommended_items:
        item["id"] = str(item.pop("_id"))
        recommended_products.append(item)

    if len(all_items) <= 0:
        recommended_products = []

    return recommended_products

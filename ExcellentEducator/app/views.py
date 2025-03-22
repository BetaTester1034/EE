from django.shortcuts import render, redirect, reverse
from django.http import HttpResponse
from django.contrib import messages
from app.utilities.db import get_db
from bson.binary import Binary
from datetime import datetime, timedelta
from bson.objectid import ObjectId
import time
import requests
from app.utilities.decorators import authenticated_only, logout_only
from django.conf import settings
import stripe
import uuid
from app.utilities.funcs import get_country_data, get_post_replies, make_premium, is_premium, check_password_breach, get_ai_response
from django.http import JsonResponse
from app.config import STRIPE_SECRET_KEY, CAPTCHA_SECRET_KEY, CAPTCHA_SITE_KEY
from app.utilities.algorithms import recommend_items
import os
import bcrypt
import json
from PyPDF2 import PdfReader, PdfWriter

from io import BytesIO

db = get_db()
stripe.api_key = STRIPE_SECRET_KEY

# Path to the default profile picture
DEFAULT_PROFILE_PICTURE_PATH = os.path.join('app', 'static', 'images', 'EE.jpg')

def validate_file_exists(file_path):
    """Check if a file exists."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Default profile picture not found: {file_path}")

def validate_form_data(form_data):
    """Validate user input."""
    required_fields = ["fullName", "dob", "guardianPhone", "address", "grade", "password", "guardianEmail"]
    for field in required_fields:
        if not form_data.get(field):
            raise ValueError(f"Missing required field: {field}")

def secure_pdf(pdf_binary_data):
    """Secures a PDF in read-only mode."""
    try:
        reader = PdfReader(BytesIO(pdf_binary_data))
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        output_stream = BytesIO()
        writer.encrypt(user_password="", owner_password="", permissions_flag=0x0004)
        writer.write(output_stream)
        secured_pdf_bytes = output_stream.getvalue()

        return secured_pdf_bytes

    except Exception as e:
        print(f"Error securing PDF: {e}")
        return None

def view_video(request, video_token):
    video_access_token = db.file_access_tokens.find_one({'token': video_token})
    if video_access_token is None:
        messages.error(request, "Invalid video access token.")
        return redirect('home')

    product_id = video_access_token['product_id']
    video = db.items.find_one({'_id': ObjectId(product_id)})
    if video is None:
        messages.error(request, "Invalid video ID.")
        return redirect('home')
    elif video.get('item_video_file') is None:
        messages.error(request, "Video file not found.")
        return redirect('home')
    elif video['item_category'] != "video":
        messages.error(request, "You may only view videos.")
        return redirect('home')

    video_binary_data = video['item_video_file']
    response = HttpResponse(video_binary_data, content_type='video/mp4')

    response['Content-Disposition'] = 'inline; filename="{}"'.format(video['item_name'])
    return response

def about_dr_fox(request):
    pdf_file = os.path.join(settings.BASE_DIR, 'app', 'static', 'about_dr_fox.pdf')

    with open(pdf_file, 'rb') as pdf_file:
        pdf_binary = pdf_file.read()

    response = HttpResponse(pdf_binary, content_type='application/pdf')

    response['Content-Disposition'] = 'inline; filename="{}"'.format('About Dr. Fox')
    return response

def view_pdf_file(request, pdf_token):
    file_access_token = db.file_access_tokens.find_one({'token': pdf_token})
    if file_access_token is None:
        messages.error(request, "Invalid file access token.")
        return redirect('home')

    product_id = file_access_token['product_id']
    item = db.items.find_one({'_id': ObjectId(product_id)})
    if item['item_category'].lower() != "pdf":
        messages.error(request, "You may only view PDFS.")
        return redirect('home')
    if item is None:
        messages.error(request, "Invalid product ID.")
        return redirect('home')

    # Your condition here (replace with your actual logic)
    try:
        is_user_premium = is_premium(str(request.session.get("user")["id"]))
    except TypeError:
        is_user_premium = False

    if not is_user_premium:
        pdf_bytes_data = secure_pdf(item['item_pdf_file'])
    else:
        pdf_bytes_data = item['item_pdf_file']

    response = HttpResponse(pdf_bytes_data, content_type='application/pdf')

    response['Content-Disposition'] = 'inline; filename="{}"'.format(item['item_name'])
    return response

@logout_only
def sign_up(request):
    if request.method == "POST":
        try:
            # Fetch and validate form data
            full_name = request.POST.get("fullName")
            dob = request.POST.get("dob")
            guardian_phone = request.POST.get("guardianPhone")
            address = request.POST.get("address")
            grade = request.POST.get("grade")
            password = request.POST.get("password")
            guardian_email = request.POST.get("guardianEmail")
            country_residence = request.POST.get("countryOfResidence")
            city = request.POST.get("city")
            nationality = request.POST.get("nationality")
            recaptcha_response = request.POST.get("g-recaptcha-response")

            url = "https://www.google.com/recaptcha/api/siteverify"
            data = {
                "secret": CAPTCHA_SECRET_KEY,
                'response': recaptcha_response
            }
            response = requests.post(url, data=data)
            result = response.json()

            if not result['success']:
                messages.error(request, "Invalid reCAPTCHA. Please try again.")
                return redirect("sign_up")

            # Validate form data
            validate_form_data(request.POST)
            
            # Check if the user already exists
            if db.users.find_one({"guardian_email": guardian_email}):
                messages.error(request, "An account with this email already exists.")
                return redirect("sign_up")
            
            if check_password_breach(password):
                messages.error(request, "The password you entered has been in past data breaches. Please choose a different password.")
                return redirect("sign_up")
            
            # Hash the password with bcrypt
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            # Validate and read the default profile picture
            validate_file_exists(DEFAULT_PROFILE_PICTURE_PATH)
            with open(DEFAULT_PROFILE_PICTURE_PATH, 'rb') as img_file:
                default_profile_picture = Binary(img_file.read())
            
            # Create user data
            new_user = {
                "full_name": full_name,
                "date_of_birth": datetime.strptime(dob, "%Y-%m-%d"),  # Parse as datetime
                "guardian_phone_no": guardian_phone,
                "guardian_email": guardian_email,
                "rank": 0,
                "address": address,
                "country_of_res": country_residence,
                "city": city,
                "nationality": nationality,
                "grade": grade,
                "password": hashed_password,  # Store as bytes
                "profile_picture": default_profile_picture,
                "creation_date": datetime.utcnow(),
            }
            
            # Save to database (MongoDB example)
            created_user = db.users.insert_one(new_user)

            # Handle IP address data
            ip_data = db.ip_addresses.find_one({'user_id': str(created_user.inserted_id)})
            if not ip_data:  # Check if IP address is already recorded
                address_data = {
                    "user_id": str(created_user.inserted_id),
                    "address": request.META.get('REMOTE_ADDR'),
                    "timestamp": datetime.utcnow(),
                    "user_agent": request.headers.get('User-Agent'),
                    "is_blocked": 0
                }
                db.ip_addresses.insert_one(address_data)

            db.logged_ip_addresses.insert_one({
                'user_id': str(created_user.inserted_id),
                'ip_address': request.META.get('REMOTE_ADDR'),
                'timestamp': datetime.utcnow(),
                'user_agent': request.headers.get('User-Agent')
            })
            request.session["user"] = {
                "id": str(created_user.inserted_id),
                "full_name": full_name,
                "guardian_email": guardian_email,
                "guardian_phone_no": guardian_phone,
                "address": address,
                "country_of_res": country_residence,
                "city": city,
                "nationality": nationality,
                "grade": grade,
                "rank": 0,
                "creation_date": str(datetime.utcnow()),
            }

            return redirect("login")

        except FileNotFoundError as e:
            messages.error(request, str(e))
        except ValueError as e:
            messages.error(request, str(e))
        except Exception as e:
            messages.error(request, "An unexpected error occurred. Please try again.")
            print(f"Error during sign up: {e}")

    countries = get_country_data()
    return render(request, 'sign_up.html', {'RECAPTCHA_PUBLIC_KEY': CAPTCHA_SITE_KEY, 'countries': countries})

@logout_only
def login(request):
    if request.method == "POST":
        try:
            # Fetch form data safely
            email = request.POST.get("email", "").strip()
            password = request.POST.get("password", "").strip()
            recaptcha_response = request.POST.get("g-recaptcha-response", "")

            # Validate reCAPTCHA
            url = "https://www.google.com/recaptcha/api/siteverify"
            data = {
                "secret": CAPTCHA_SECRET_KEY,
                "response": recaptcha_response
            }
            response = requests.post(url, data=data)
            result = response.json()

            if not result.get("success"):
                messages.error(request, "Invalid reCAPTCHA. Please try again.")
                return redirect("login")

            if not email or not password:
                messages.error(request, "Both email and password are required.")
                return redirect("login")

            # Check if user exists
            user = db.users.find_one({"guardian_email": email})

            if user:
                stored_password = user.get("password", "")

                if bcrypt.checkpw(password.encode("utf-8"), stored_password):
                    # Check if IP is already logged
                    ip_address = request.META.get("REMOTE_ADDR")
                    ip_data = db.ip_addresses.find_one({"user_id": str(user["_id"])})

                    if not ip_data:
                        address_data = {
                            "user_id": str(user["_id"]),
                            "address": ip_address,
                            "timestamp": datetime.utcnow(),
                            "user_agent": request.headers.get("User-Agent"),
                            "is_blocked": 0
                        }
                        db.ip_addresses.insert_one(address_data)

                    # Log IP if not already logged
                    if not db.logged_ip_addresses.find_one({"user_id": str(user["_id"]), "ip_address": ip_address}):
                        db.logged_ip_addresses.insert_one({
                            "user_id": str(user["_id"]),
                            "ip_address": ip_address,
                            "timestamp": datetime.utcnow(),
                            "user_agent": request.headers.get("User-Agent")
                        })

                    # Store user session
                    request.session["user"] = {
                        "id": str(user["_id"]),
                        "full_name": user.get("full_name", ""),
                        "guardian_email": user.get("guardian_email", ""),
                        "guardian_phone_no": user.get("guardian_phone_no", ""),
                        "address": user.get("address", ""),
                        "country_of_res": user.get("country_of_res", ""),
                        "city": user.get("city", ""),
                        "nationality": user.get("nationality", ""),
                        "grade": user.get("grade", ""),
                        "rank": user.get("rank", ""),
                        "creation_date": str(user.get("creation_date", ""))
                    }
                    return redirect("home")
                else:
                    messages.error(request, "Invalid email or password.")
                    return redirect("login")

            else:
                messages.error(request, "No account found with that email.")
                return redirect("login")

        except Exception as e:
            messages.error(request, "An unexpected error occurred. Please try again.")
            print(f"Error during login: {e}")
            return redirect("login")

    return render(request, "login.html", {"RECAPTCHA_PUBLIC_KEY": CAPTCHA_SITE_KEY})

@authenticated_only
def home(request):
    try:
        user = request.session.get("user")
        posts_collection = db["posts"]
        posts_cursor = posts_collection.find()

        posts = []
        
        for post in posts_cursor:
            post["id"] = str(post.pop("_id"))

            # Reset replies for each post
            replies = get_post_replies(post['id'])
            if not replies:
                print(f"No replies found for post: {post['id']}")
            else:
                for reply in replies:
                    reply['is_premium_user'] = is_premium(reply['author_id'])

            post['replies'] = replies  # Assign replies to the post
            posts.append(post)

        return render(request, "home.html", {"user": user, "posts": posts})
    
    except Exception as e:
        messages.error(request, "An unexpected error occurred. Please try again.")
        print(f"Error during home page rendering: {e}")
        return redirect("login")

@authenticated_only
def pricing_plans(request):
    if is_premium(request.session.get('user')['id']):
        messages.error(request, "You are already a premium user")
        return redirect('my_subscription')
    price_id = "price_1Qv6MdFM2mYIuytCmfYwh9bh"
    if request.method == "POST":
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    "price": price_id,
                    "quantity": 1,
                },
            ],
            payment_method_types=["card"],
            mode="subscription",
            success_url=request.build_absolute_uri(reverse("create_subscription")) + f"?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=request.build_absolute_uri(reverse("home")),
            customer_email=request.session.get("user")["guardian_email"],
            metadata = {
                'user_id': request.session.get("user")["id"]
            }
        )
        return redirect(checkout_session.url, code=303)

    return render(request, "pricing_plans.html")

@authenticated_only
def cancel_subscription(request):
    if not is_premium(request.session.get('user')['id']):
        messages.error(request, "You are not a premium user")
        return redirect('my_subscription')

    user = request.session["user"]
    subp_record = db.subscriptions.find_one({"user_id": user["id"], 'status': 'Active'})

    if "subscription_id" in subp_record and "charge_id" in subp_record:
        stripe.Subscription.delete(subp_record["subscription_id"], cancel_at_period_end=True)

    messages.success(request, "Your subscription has been cancelled")

    return redirect('my_subscription')

@authenticated_only
def create_subscription(request):
    checkout_session_id = request.GET.get('session_id', None)
    
    try:
        session = stripe.checkout.Session.retrieve(checkout_session_id)
    except Exception as e:
        messages.error(request, "Invalid session id")
        print(e)
        return redirect('home')

    session_id_used = db.used_session_ids.find_one({"session_id": checkout_session_id})
    if session_id_used is not None:
        messages.error(request, "This session has already been used for a subscription")
        return redirect('home')

    # Retrieve the Subscription linked to the session
    subscription_id = session.subscription

    subscription = stripe.Subscription.retrieve(subscription_id)
    payment_method_data = stripe.PaymentMethod.retrieve(subscription.default_payment_method)

    if db.billing.find_one({'user_id': str(request.session.get("user")["id"])}) is None:
        db.billing.insert_one({
            "user_id": str(request.session.get("user")["id"]),
            "card_brand": payment_method_data['card']['brand'],
            "card_last_4_digits": payment_method_data['card']['last4'],
            "expiration_date": f"{payment_method_data['card']['exp_month']}/{payment_method_data['card']['exp_year']}",
            "country": payment_method_data['card']['country'],
            "name": payment_method_data['billing_details']['name']
        })

    invoice = stripe.Invoice.retrieve(subscription.latest_invoice)
    charge_id = invoice.charge

    db.used_session_ids.insert_one({"session_id": checkout_session_id})
    db.subscriptions.insert_one({
        "user_id": str(request.session.get("user")["id"]),
        "subscription_id": subscription_id,
        "charge_id": charge_id,
        "start_date": int(time.time()),
        "end_date": int(time.time()) + 31536000,
        "status": "Active"
    })
    db.purchase_history.insert_one({"user_id": str(request.session.get("user")["id"]), 'purchase_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'item_name': 'Premium Subscription', 'item_price': 100.00, 'charge_id': charge_id})

    # Finally, redirect to 'my_subscription' page
    return redirect('my_subscription')

@authenticated_only
def buy_shop_item(request, item_id):
    try:
        item = db.items.find_one({"_id": ObjectId(item_id)})
        if item is None:
            messages.error(request, "Item not found.")
            return redirect("shop")

        if not is_premium(request.session.get("user")["id"]) and item['item_is_premium'] == 'on':
            messages.error(request, "You are not a premium user to buy this")
            return redirect('shop')
        
        product_price_id = item.get("stripe_price_id")
        if product_price_id is None:
            messages.error(request, "Item is not for sale.")
            return redirect("shop")

        if is_premium(request.session.get("user")["id"]):
            new_stripe_price = stripe.Price.create(
                unit_amount=0,
                currency="usd",
                product=str(item['stripe_product_id']),
            )
            product_price_id = new_stripe_price.id

        # Handle user being logged in or not
        user = request.session.get("user", None)
        user_id = user.get("id") if user else None
        user_email = user.get("guardian_email") if user else None

        # If user is logged in, use their details, otherwise set defaults
        if not user_email:
            # If no user email is available, handle accordingly (e.g., use a generic email or request for email)
            user_email = "guest@domain.com"  # or some default email

        # Create Stripe checkout session
        checkout_session = stripe.checkout.Session.create(
            line_items=[{
                "price": product_price_id,
                "quantity": 1,
            }],
            payment_method_types=["card"],
            mode="payment",
            success_url=request.build_absolute_uri(reverse("create_item_purchase")) + f"?session_id={{CHECKOUT_SESSION_ID}}&product_id={item_id}",
            cancel_url=request.build_absolute_uri(reverse("home")),
            customer_email=user_email,  # Use guest email if not logged in
            metadata={'user_id': user_id}  # Store user_id (even if None)
        )
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        messages.error(request, "An error occurred while processing your purchase.")
        print(e)
        return redirect("shop")
    
def create_item_purchase(request):
    checkout_session_id = request.GET.get('session_id', None)
    product_id = request.GET.get('product_id')

    try:
        session = stripe.checkout.Session.retrieve(checkout_session_id)
    except Exception as e:
        print(e)
        messages.error(request, "Invalid session id")
        return redirect('home')

    session_id_used = db.used_session_ids.find_one({"session_id": checkout_session_id})
    if session_id_used is not None:
        messages.error(request, "This session has already been used for an item purchase")
        return redirect('home')

    product = db.items.find_one({'_id': ObjectId(product_id)})

    payment_intent_id = session.payment_intent

    if payment_intent_id is None:
        payment_method = None
    else:
        payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)
        payment_method_id = payment_intent.payment_method
        payment_method = stripe.PaymentMethod.retrieve(payment_method_id)

    # Store billing details only if a payment method exists
    if payment_method and request.session.get("user", None) is not None and db.billing.find_one({'user_id': str(request.session.get("user")["id"])}) is None:
        db.billing.insert_one({
            "user_id": str(request.session.get("user")["id"]),
            "card_brand": payment_method['card']['brand'],
            "card_last_4_digits": payment_method['card']['last4'],
            "expiration_date": f"{payment_method['card']['exp_month']}/{payment_method['card']['exp_year']}",
            "country": payment_method['card']['country'],
            "name": payment_method['billing_details']['name']
        })
    db.used_session_ids.insert_one({"session_id": checkout_session_id})
    purchase_history_data = {
        'purchase_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'item_name': product["item_name"],
        'item_price': product["item_price"]
    }
    if request.session.get("user", None) is not None:
        purchase_history_data["user_id"] = str(request.session.get("user")["id"])

    db.purchase_history.insert_one(purchase_history_data)

    token = str(uuid.uuid4())
    collection_data = {
        "product_id": product_id,
        "token": token,
        "account_owner": "false" if request.session.get("user", None) is None else "true",
    }
    if request.session.get("user", None) is not None:
        collection_data["user_id"] = request.session.get("user")["id"]

    db.file_access_tokens.insert_one(collection_data)
    if product["item_category"].lower() == "pdf":
        return redirect('view_pdf_file', pdf_token=token)
    else:
        return redirect('view_video', video_token=token)


@authenticated_only
def view_bought_resources(request):
    user = request.session["user"]
    all_res = db.file_access_tokens.find({'user_id': str(user["id"])})
    all_resources = []
    for res in all_res:
        product = db.items.find_one({'_id': ObjectId(res["product_id"])})
        if product is not None:
            res["product_name"] = product["item_name"]
            res["product_description"] = product["item_description"]
            res["product_category"] = product["item_category"]
            res_token = res["token"]
            res["view_link"] = f"/view_pdf_file/{res_token}" if product["item_category"].lower() == "pdf" else f"/view_video_file/{res_token}"
        else:
            res["product_name"] = None
        if product is not None:
            all_resources.append(res)

    return render(request, "bought_resources.html", {"all_resources": all_resources})
    
@authenticated_only
def my_subscription(request):
    start_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    end_date = (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S')
    subscription_data = {
        'start_date': start_date,
        'renewal_date': end_date,
        'is_premium': is_premium(str(request.session.get("user")["id"]))
    }
    return render(request, "my_subscription.html", {"subscription_data": subscription_data})

@authenticated_only
def shop(request):
    # Get the user from session
    user = request.session.get("user")
    
    # Fetch all items from the MongoDB collection
    items = db.items.find()  # Fetches all items
    
    # Convert the items to a list, so we can pass them to the template
    items_list = list(items)
    items = []

    for item in items_list:
        item["id"] = str(item.pop("_id"))
        items.append(item)

    if user:
        recommended_items = recommend_items(user.get("id"))
    else:
        recommended_items = []

    user['has_premium'] = is_premium(user.get("id"))

    all_premium_items_length = 0
    for item in items:
        if item["item_is_premium"] == "on":
            all_premium_items_length += 1
    
    # Pass the user and items to the template
    return render(request, "shop.html", {'user': user, 'items': list(items), 'recommended_items': list(recommended_items), "is_premium": is_premium(user.get("id")), 'premium_items_exist': all_premium_items_length > 0})

@authenticated_only
def user_settings(request):
    if request.method == "POST":
        # Recieve image file for new pfp given by user in the form
        image_file = request.FILES.get("profile_picture")
        if image_file:
            # Convert the image file to binary data
            image_data = image_file.read()

            # Update the user's profile picture in the database
            db.users.update_one({"_id": ObjectId(request.session.get("user")["id"])}, {"$set": {"profile_picture": image_data}})
            messages.success(request, "Profile picture updated successfully.")
            return redirect('user_settings')
        else:
            messages.error(request, "Please select a file.")
            return redirect('user_settings')
    return render(request, "user_settings.html", {'user_id': request.session.get("user")["id"]})

@authenticated_only
def get_ai_res(request):
    if request.method == 'POST':
        try:
            # Parse the JSON data from the request body
            data = json.loads(request.body)
            prompt = data.get('prompt', None)
            
            if prompt:
                print(prompt)
                ai_response = get_ai_response(prompt)
                return JsonResponse({"response": ai_response})
            else:
                return JsonResponse({"error": "No prompt found"}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data"}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=405)
    
@authenticated_only
def ai_chat(request):
    return render(request, 'ai_chat.html')

@authenticated_only
def reply_post(request, post_id):
    if request.method == "POST":
        post = db.posts.find_one({'_id': ObjectId(post_id)})
        if post is None:
            messages.error(request, "Post not found.")
            return redirect("home")
        if post["post_for"] != request.session.get("user")["grade"] and request.session.get("user")["rank"] == 0:
            messages.error(request, "You are not authorized to reply to this post.")
            return redirect("home")
        message = request.POST.get("reply-content")
        if not message:
            messages.error(request, "Please enter a message.")
            return redirect("reply_post", post_id=post_id)

        # Insert the reply into the database
        reply = {
            'author_id': request.session.get("user")["id"],
            'author_name': request.session.get("user")["full_name"],
            'post_id': post_id,
            'reply_content': message,
            'reply_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        db.replies.insert_one(reply)

        messages.success(request, "Your reply has been posted successfully.")
        return redirect("home")
    return render(request, "reply_post.html")

def get_profile_picture(request, user_id):
    try:
        user = db.users.find_one({"_id": ObjectId(user_id)})
        if not user or not user.get("profile_picture"):
            raise ValueError("Profile picture not found.")
        
        # Return the binary image data
        return HttpResponse(user["profile_picture"], content_type="image/jpeg")
    except Exception as e:
        print(f"Error fetching profile picture: {e}")
        return HttpResponse(status=404)   

@authenticated_only
def logout(request):
    if not request.session.get("user"):
        return redirect("login")

    request.session.pop("user", None)
    return redirect("login")
from app.utilities.db import get_db
from django.shortcuts import render, redirect
from django.contrib import messages
from datetime import datetime
from app.utilities.decorators import admin_only
from app.utilities.funcs import is_premium, get_subscription_data, convert_timestamp_to_date, get_total_sales, check_password_breach
from app.config import STRIPE_SECRET_KEY
import bcrypt
import time
import stripe
from bson.objectid import ObjectId

stripe.api_key = STRIPE_SECRET_KEY
db = get_db()

@admin_only
def admin_dashboard(request):
    if request.method == "POST":
        form_type = request.POST.get('formType')
        if form_type == "blockIP":
            ip_address = request.POST.get('ip_address')
            return redirect('block_ip', ip_address=ip_address)
        elif form_type == "unblockIP":
            ip_address = request.POST.get('ip_address')
            return redirect('unblock_ip', ip_address=ip_address)

    users_collection = db["users"]
    cursor = users_collection.find()

    # Clone the cursor to avoid consuming it prematurely
    all_students = []
    for user in cursor:
        user["id"] = str(user.pop("_id"))
        user["account_type"] = "Premium" if is_premium(user["id"]) else "Regular"
        all_students.append(user)  # Remove the _id field

    blocked_ips = list(db.ip_addresses.find({'is_blocked': 1}))

    products_base = db.items.find()
    all_prodcuts = []

    for product in products_base:
        product["id"] = str(product.pop("_id"))
        all_prodcuts.append(product)


    return render(request, 'admin/dashboard.html', {'users': all_students, 'current_user': request.session.get('user'), 'total_sales': get_total_sales(), 'all_products': all_prodcuts, 'blocked_ips': blocked_ips})

def teachers_only(request):
    return render(request, "errors/teachers_only.html")

def create_stripe_product(item_name, item_price, item_description):
    stripe_product = stripe.Product.create(
        name=item_name,
        description=item_description,
    )
    stripe_price = stripe.Price.create(
        unit_amount=int(item_price * 100),  # Price in cents
        currency="usd",
        product=stripe_product.id,
    )
    return stripe_product.id, stripe_price.id  # Return both product and price ID
@admin_only
def add_item(request):
    if request.method == "POST":
        item_name = request.POST.get("item_name")
        item_price = request.POST.get("item_price")
        item_description = request.POST.get("item_description")
        item_pdf = request.FILES.get("item_pdf")
        item_video = request.FILES.get("item_video")
        item_is_premium = request.POST.get("item_is_premium")
        item_category = request.POST.get("item_category")

        pdf_binary_data = None
        video_binary_data = None
        

        if not item_name or not item_price or not item_description:
            messages.error(request, "All fields are required.")
            return redirect("add_item")
        
        if item_category.lower() == "pdf":
            pdf_binary_data = item_pdf.read()
        else:
            video_binary_data = item_video.read()

        # Validate price
        try:
            item_price = float(item_price)
            if item_price <= 0:
                raise ValueError("Price must be a positive number.")
        except ValueError as e:
            messages.error(request, f"Invalid price: {e}")
            return redirect("add_item")  # Redirect to the same page

        # Create the Stripe product and price
        stripe_product_id, stripe_price_id = create_stripe_product(item_name, item_price, item_description)

        if item_category.lower() == "pdf":
            item_data = {
                "item_name": item_name,
                "item_price": item_price,
                "item_description": item_description,
                "item_pdf_file": pdf_binary_data,
                "stripe_product_id": stripe_product_id,
                "stripe_price_id": stripe_price_id,
                "item_is_premium": item_is_premium,
                "item_category": item_category
            }
        else:
            item_data = {
                "item_name": item_name,
                "item_price": item_price,
                "item_description": item_description,
                "item_video_file": video_binary_data,
                "stripe_product_id": stripe_product_id,
                "stripe_price_id": stripe_price_id,
                "item_is_premium": item_is_premium,
                "item_category": item_category
            }

        db["items"].insert_one(item_data)

        messages.success(request, "Item added successfully.")
        from_page = request.GET.get("from_page", None)
        if from_page == "dashboard":
            return redirect("admin_dashboard")
        else:
            return redirect("shop")

    return render(request, "admin/add_item.html")

@admin_only
def new_post(request):
    if request.method == "POST":
        post_content = request.POST.get("content")
        post_type = request.POST.get("post_type")
        post_for = request.POST.get("post_for")
        post_date = datetime.now().strftime("%d/%m/%Y %H:%M")
        post_author = request.session.get('user')['id']

        post_data = {
            "author_id": post_author,
            "author_name": request.session.get('user')['full_name'],
            "post_type": post_type,
            "post_date": post_date,
            "post_for": post_for,
            "post_content": post_content
        }

        db["posts"].insert_one(post_data)

        messages.success(request, "Post created successfully.")
        return redirect("new_post")

    return render(request, "admin/new_post.html")


@admin_only
def edit_post(request, post_id):
    if request.method == "POST":
        post_content = request.POST.get("content")
        post_type = request.POST.get("post_type")

        post_data = {
            "post_type": post_type,
            "post_content": post_content
        }

        db["posts"].update_one({"_id": ObjectId(post_id)}, {"$set": post_data})

        messages.success(request, "Post updated successfully.")
        return redirect("home")
    
    post = db["posts"].find_one({"_id": ObjectId(post_id)})
    return render(request, "admin/edit_post.html", {"post": post})

@admin_only
def delete_post(request, post_id):
    db["posts"].delete_one({"_id": ObjectId(post_id)})
    messages.success(request, "Post deleted successfully.")
    return redirect("home")

@admin_only
def convert_to_premium(request, user_id):
    # Make sure user account isnt premium already
    if is_premium(user_id):
        messages.error(request, "User is already premium")
        return redirect("admin_dashboard")
    
    db.subscriptions.insert_one({
        "user_id": str(user_id),
        "start_date": int(time.time()),
        "end_date": int(time.time()) + 31536000,
        "status": "Active"
    })
    from_page = request.GET.get('from_page')
    messages.success(request, "User account upgraded to premium successfully.")
    if from_page == "manage_user":
        return redirect("manage_user", user_id=user_id)
    
    return redirect("admin_dashboard")

@admin_only
def cancel_subscription(request, user_id):
    if not is_premium(str(user_id)):
        from_page = request.GET.get('from_page')
        messages.error(request, "User is not premium")
        if from_page == "manage_user":
            return redirect("manage_user", user_id=user_id)
        return redirect("admin_dashboard")
    
    db.subscriptions.update_many({"user_id": user_id}, {"$set": {"status": "Cancelled"}})
    from_page = request.GET.get('from_page')
    messages.success(request, "User subscription cancelled successfully.")

    if from_page == "manage_user":
        return redirect("manage_user", user_id=user_id)
    return redirect("admin_dashboard")

@admin_only
def block_ip(request, ip_address):
    from_page = request.GET.get('from_page')

    ip_entry = db.ip_addresses.find_one({'address': ip_address})
    if ip_entry is not None:
        db.ip_addresses.update_one({"address": str(ip_address)}, {"$set": {"is_blocked": 1}})
    else:
        db.ip_addresses.insert_one({"address": ip_address, "is_blocked": 1, 'timestamp': datetime.utcnow()})
        ip_entry = db.ip_addresses.find_one({'address': ip_address})

    user_id = ip_entry.get('user_id', None)

    messages.success(request, "IP address blocked successfully.")

    if from_page == "manage_user" and user_id is not None:
        return redirect("manage_user", user_id=user_id)
    return redirect('admin_dashboard')

@admin_only
def unblock_ip(request, ip_address):
    from_page = request.GET.get('from_page')

    ip_entry = db.ip_addresses.find_one({'address': ip_address})
    if ip_entry is not None:
        db.ip_addresses.update_one({"address": str(ip_address)}, {"$set": {"is_blocked": 0}})
    else:
        messages.error(request, "IP address is not blocked.")

    user_id = ip_entry.get('user_id', None)

    messages.success(request, "IP address unblocked successfully.")

    if from_page == "manage_user" and user_id is not None:
        return redirect("manage_user", user_id=user_id)
    return redirect('admin_dashboard')

@admin_only
def delete_product(request, product_id):
    from_page = request.GET.get('from_page')

    product = db.items.find_one({'_id': ObjectId(product_id)})

    if product:
        stripe_product_id = product.get("stripe_product_id")
        stripe_price_id = product.get("stripe_price_id")

        if stripe_price_id:
            stripe.Price.modify(stripe_price_id, active=False)  # Deactivate price instead of deleting

        if stripe_product_id:
            stripe.Product.modify(stripe_product_id, active=False)  # Deactivate product instead of deleting

        db.file_access_tokens.delete_many({"product_id": product_id})
        db.items.delete_one({"_id": ObjectId(product_id)})
        messages.success(request, "Product deactivated and removed successfully")
    else:
        messages.error(request, "No product found with that ID")

    return redirect("admin_dashboard" if from_page == "dashboard" else "shop")

@admin_only
def delete_account(request, user_id):
    user = db.users.find_one({"_id": ObjectId(user_id)})
    from_page = request.GET.get('from_page')
    if not user:
        messages.error(request, "User not found")
        if from_page == "manage_user":
            return redirect("manage_user", user_id=user_id)


    db.users.delete_one({"_id": ObjectId(user_id)})

    messages.success(request, "User account deleted successfully.")

    if from_page == "manage_user":
        return redirect("manage_user", user_id=user_id)
    else:
        return redirect("admin_dashboard")

@admin_only
def edit_product(request, product_id):
    if request.method == "POST":
        product_title = request.POST.get("product_title")
        product_description = request.POST.get("product_description")
        product_price = float(request.POST.get("product_price"))

        product = db.items.find_one({"_id": ObjectId(product_id)})

        stripe_price = stripe.Price.create(
            unit_amount=int(product_price * 100),
            currency="usd",
            product=product["stripe_product_id"],
        )

        product_data = {
            "item_name": product_title,
            "item_price": product_price,
            "item_description": product_description,
            "stripe_price_id": stripe_price.id
        }

        db.items.update_one({"_id": ObjectId(product_id)}, {"$set": product_data})

        messages.success(request, "Product updated successfully.")
        return redirect("home")
    
    product = db["items"].find_one({"_id": ObjectId(product_id)})
    return render(request, "admin/edit_product.html", {"product": product})
    
@admin_only
def edit_user(request, user_id):
    if request.method == "POST":
        user = db.users.find_one({"_id": ObjectId(user_id)})
        if user is None:
            messages.error(request, "User not found")
            return redirect("admin_dashboard")
        
        full_name = request.POST.get("full_name")
        email = request.POST.get("email")
        phone_number = request.POST.get("phone_number")
        address = request.POST.get("address")
        city = request.POST.get("city")
        nationality = request.POST.get("nationality")
        country_of_res = request.POST.get("country_of_res")
        year = request.POST.get("year")

        db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {
            "full_name": full_name,
            "guardian_email": email,
            "guardian_phone_no": phone_number,
            "address": address,
            "country_of_res": country_of_res,
            "city": city,
            "nationality": nationality,
            "grade": year
        }})

        messages.success(request, "User updated successfully.")
        return redirect("manage_user", user_id=user_id)


    else:
        user = db.users.find_one({"_id": ObjectId(user_id)})
        return render(request, "admin/edit_user.html", {"user": user})

@admin_only
def manage_user(request, user_id):
    if request.method == "POST":
        formType = request.POST.get("formType")
        if formType == "resetPassword":
            newPassword = request.POST.get("new_password")
            confirmPassword = request.POST.get("confirm_password")
            if newPassword != confirmPassword:
                messages.error(request, "Passwords do not match.")
                return redirect("manage_user", user_id=user_id)
            elif len(newPassword) < 8:
                messages.error(request, "Password must be at least 8 characters long.")
                return redirect("manage_user", user_id=user_id)
            elif check_password_breach(newPassword):
                messages.error(request, "Password is too weak.")
                return redirect("manage_user", user_id=user_id)
            else:
                hashed_password = bcrypt.hashpw(newPassword.encode('utf-8'), bcrypt.gensalt())
                db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"password": hashed_password}})
                messages.success(request, "Password updated successfully.")
                return redirect("manage_user", user_id=user_id)
    else:
        user = db["users"].find_one({"_id": ObjectId(user_id)})
        is_prem = is_premium(user_id)
        subp_data = get_subscription_data(user_id)
        all_subscriptions = db.subscriptions.find({"user_id": str(user_id), "status": "Cancelled"})
        all_subps = []

        # Make sure that the start_date and end_date keys are present in subp_data
        if "start_date" in subp_data and "end_date" in subp_data:
            subp_data["start_date"] = convert_timestamp_to_date(subp_data["start_date"])
            subp_data["end_date"] = convert_timestamp_to_date(subp_data["end_date"])

        for sub in all_subscriptions:
            sub["start_date"] = convert_timestamp_to_date(sub["start_date"])
            sub["end_date"] = convert_timestamp_to_date(sub["end_date"])
            all_subps.append(sub)

        billing_info = db.billing.find_one({"user_id": str(user_id)})
        has_billing_info = billing_info is not None

        purchase_history = list(db.purchase_history.find({'user_id': str(user_id)}))
        logged_ip_addresses = list(db.logged_ip_addresses.find({'user_id': str(user_id)}))

        return render(request, "admin/manage_user.html", {"user": user, 'is_prem': is_prem, 'subp_data': subp_data, 'user_id': user['_id'], 'all_subscriptions': all_subps, 'has_billing_info': has_billing_info, 'billing_info': billing_info, 'purchase_history': purchase_history, 'logged_ip_addresses': logged_ip_addresses})
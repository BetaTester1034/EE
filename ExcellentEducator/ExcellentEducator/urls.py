"""
URL configuration for ExcellentEducator project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from app import views
from app import admin_views

urlpatterns = [
    path('', views.sign_up, name='sign_up'),
    path('login/', views.login, name='login'),
    path('home/', views.home, name='home'),
    path('logout/', views.logout, name='logout'),
    path('profile-picture/<str:user_id>/', views.get_profile_picture, name='profile_picture'),
    path('pricing-plans/', views.pricing_plans, name='pricing_plans'),
    path('shop/', views.shop, name='shop'),
    path('admin/dashboard/', admin_views.admin_dashboard, name='admin_dashboard'),
    path('teachers_only/', admin_views.teachers_only, name='teachers_only'),
    path('admin/new-post/', admin_views.new_post, name='new_post'),
    path('admin/edit-post/<str:post_id>/', admin_views.edit_post, name='edit_post'),
    path('admin/delete-post/<str:post_id>/', admin_views.delete_post, name='delete_post'),
    path('reply-post/<str:post_id>/', views.reply_post, name='reply_post'),
    path('admin/convert_to_premium/<str:user_id>/', admin_views.convert_to_premium, name='convert_to_premium'),
    path('create-subscription/', views.create_subscription, name='create_subscription'),
    path('my_subscription/', views.my_subscription, name='my_subscription'),
    path('admin/cancel_subscription/<str:user_id>/', admin_views.cancel_subscription, name='cancel_subscription'),
    path('admin/manage-user/<str:user_id>/', admin_views.manage_user, name='manage_user'),
    path('admin/add-item/', admin_views.add_item, name='add_item'),
    path('admin/block-ip/<str:ip_address>/', admin_views.block_ip, name='block_ip'),
    path('admin/unblock-ip/<str:ip_address>/', admin_views.unblock_ip, name='unblock_ip'),
    path('create_item_purchase', views.create_item_purchase, name='create_item_purchase'),
    path('buy_shop_item/<str:item_id>', views.buy_shop_item, name='buy_shop_item'),
    path('view_pdf_file/<str:pdf_token>', views.view_pdf_file, name='view_pdf_file'),
    path('view_video_file/<str:video_token>', views.view_video, name='view_video'),
    path('admin/delete-product/<str:product_id>', admin_views.delete_product, name='delete_product'),
    path('admin/delete_user/<str:user_id>', admin_views.delete_account, name='delete_account'),
    path('admin/edit_product/<str:product_id>', admin_views.edit_product, name='edit_product'),
    path('admin/edit_user/<str:user_id>', admin_views.edit_user, name='edit_product'),
    path('cancel_subscription', views.cancel_subscription, name='cancel_subscription'),
    path('about_me', views.about_dr_fox, name='about_dr_fox'),
    path('view_bought_resources', views.view_bought_resources, name='view_bought_resources'),
    path('settings', views.user_settings, name='user_settings'),
    path('get_ai_response', views.get_ai_res, name='get_ai_res'),
    path('ai_chat', views.ai_chat, name='ai_chat'),
]

from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    # home
    path('', views.home_view,name='home'),

    # auth
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    #  dashboard
    path('dashboard/',views.dashboard_view,name='dashboard'),

    # room
    
]
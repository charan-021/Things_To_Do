#msapp urls

from django.urls import path
from . import views

urlpatterns = [
    path('', views.login, name='login'),
    path('signup/', views.signup, name='signup'),
    path('terms_and_conditions/', views.terms_and_conditions, name='terms_and_conditions'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
    path('login/', views.login, name='login'),
    path('signout/', views.signout, name='signout'),
    
    path('forget_password_email/', views.forget_password_email, name='forget_password_email'),
    path('new_password/<uidb64>/<token>/', views.new_password, name='new_password'),

    path('home/', views.home, name='home'),
    path('add/', views.add, name='add'),
    path('delete/<int:id>/', views.delete, name='delete'),
    path('isco/<int:id>/', views.iscompleted, name='iscompleted'),
]


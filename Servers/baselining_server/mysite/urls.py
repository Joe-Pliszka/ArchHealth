
from django.urls import path
from main import views

urlpatterns = [
    path('', views.home),
    path('sub1/', views.sub1),
    path('sub1/sub2/', views.sub2),
    path('sub1/sub2/sub3/', views.sub3),
    path('about/', views.about),
    path('contact/', views.contact),
]

import time
import random
from django.shortcuts import render

def home(request):
    return render(request, 'main/home.html')

def sub1(request):
    return render(request, 'main/sub1.html')

def sub2(request):
    return render(request, 'main/sub2.html')

def sub3(request):
    return render(request, 'main/sub3.html')

def about(request):
    return render(request, 'main/about.html')

def contact(request):
    return render(request, 'main/contact.html')

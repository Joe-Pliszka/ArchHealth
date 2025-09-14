import time
import random
from django.shortcuts import render

def home(request):
    time.sleep(random.uniform(0.001, .01))
    return render(request, 'main/home.html')

def sub1(request):
    time.sleep(random.uniform(0.01, .1))
    return render(request, 'main/sub1.html')

def sub2(request):
    time.sleep(random.uniform(0.1, 0.5))
    return render(request, 'main/sub2.html')

def sub3(request):
    time.sleep(random.uniform(0.5, 1.5))
    return render(request, 'main/sub3.html')

def about(request):
    time.sleep(random.uniform(1.5, 2.5))
    return render(request, 'main/about.html')

def contact(request):
    time.sleep(random.uniform(2.5, 3.5))
    return render(request, 'main/contact.html')

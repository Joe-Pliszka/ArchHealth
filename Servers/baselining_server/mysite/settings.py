
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SECRET_KEY = 'fake-key-for-demo'
DEBUG = True
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.staticfiles',
    'main',
]

MIDDLEWARE = []

ROOT_URLCONF = 'mysite.urls'

TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [os.path.join(BASE_DIR, '../main/templates')],
    'APP_DIRS': True,
    'OPTIONS': {},
}]

WSGI_APPLICATION = 'mysite.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, '../db.sqlite3'),
    }
}

STATIC_URL = '/static/'

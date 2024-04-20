from django.urls import path
from . import views


urlpatterns = [
    path('', views.image_view, name='image'),
    path('encryption/', views.encryption_view, name='encryption'),
    path('decryption/', views.decryption_view, name='decryption'),
]
from django.urls import path
from . import views

app_name = 'encryption'


urlpatterns = [
    path('', views.index, name='index'),
    path('encryption/', views.encryption_view, name='encryption'),
    path('decryption/', views.decryption_view, name='decryption'),
    path('get_rsa_keys/', views.get_rsa_keys, name='get_rsa_keys'),
    path('encrypt_aes/', views.encrypt_aes, name='encrypt_aes'),
    path('encrypt_rsa/', views.encrypt_rsa, name='encrypt_rsa'),
    path('decrypt_aes/', views.decrypt_aes, name='decrypt_aes'),
    path('decrypt_rsa/', views.decrypt_rsa, name='decrypt_rsa'),
]

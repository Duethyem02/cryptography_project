from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import base64
import binascii
import re


# Create your views here.
def index(request):
    return render(request, "encryption/index.html")


def encryption_view(request):
    return render(request, "encryption/encryption.html")


def decryption_view(request):
    return render(request, "encryption/decryption.html")


#---------------- Enccryption -------------------------------_#
# Function to pad the text for AES encryption
def pad(s):
    pad_byte = AES.block_size - len(s) % AES.block_size
    return s + bytes([pad_byte] * pad_byte)


@csrf_exempt
def encrypt_aes(request):
    text = request.POST.get('text').encode('utf-8')
    hex_key = request.POST.get('key')
    hex_iv = request.POST.get('iv')

    # Convert the hexadecimal key to bytes
    try:
        key = binascii.unhexlify(hex_key)
    except binascii.Error:
        return JsonResponse({'error': 'Invalid AES key. Key must be a 64-character hexadecimal string.'},
                            status=400)

    # Validate the key length for AES-256
    if len(key) != 32:
        return JsonResponse({'error': 'Incorrect AES key length. Key must be 32 bytes (256 bits) long.'},
                            status=400)

    # If the user provides an IV, validate its length after decoding from hex
    if hex_iv:
        try:
            iv = binascii.unhexlify(hex_iv)
        except binascii.Error:
            return JsonResponse({'error': 'Invalid IV. IV must be a 32-character hexadecimal string.'},
                                status=400)
        if len(iv) != AES.block_size:
            return JsonResponse({'error': 'Incorrect IV length. IV must be 16 bytes (128 bits) long.'},
                                status=400)
    else:
        # Generate a random IV
        iv = get_random_bytes(AES.block_size)
        # Convert the IV to a hexadecimal string
        hex_iv = binascii.hexlify(iv).decode('utf-8')

    # Encrypt the text
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_text = base64.b64encode(cipher.encrypt(pad(text))).decode('utf-8')
    except (ValueError, KeyError, binascii.Error) as e:
        return JsonResponse({'error': 'Encryption failed. ' + str(e)},
                            status=400)

    return JsonResponse({
        'encrypted_text': encrypted_text,
        'iv': hex_iv,  # Send the IV as a hexadecimal string
        'key': hex_key  # Send the key as it was received (hexadecimal)
    })


# Function to generate RSA key pair
def generate_rsa_keypair():
    key = RSA.generate(2048)  # Generate a 2048-bit RSA key pair
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


@csrf_exempt
def get_rsa_keys(request):
    private_key, public_key = generate_rsa_keypair()
    return JsonResponse({
        'private_key': private_key.decode('utf-8'),
        'public_key': public_key.decode('utf-8')
    })


@csrf_exempt
def encrypt_rsa(request):
    public_key_string = request.POST.get('public_key')
    text = request.POST.get('text').encode('utf-8')  # Ensure text is in bytes

    # Check if the public key is provided
    if not public_key_string:
        return JsonResponse({'error': 'No public key provided. Please provide a valid RSA public key.'}, status=400)

    try:
        rsa_key = RSA.import_key(public_key_string)  # Import the user-provided public key
    except (ValueError, IndexError):
        return JsonResponse({'error': 'Invalid public key format. Please provide a public key in the correct format.'},
                            status=400)

    cipher = PKCS1_OAEP.new(rsa_key)  # Create a cipher object
    encrypted_text = base64.b64encode(cipher.encrypt(text)).decode('utf-8')
    return JsonResponse({'encrypted_text': encrypted_text})


#---------------- Decryption -------------------------------_#
# Function to remove padding for AES decryption
def unpad(s):
    return s[:-s[-1]]


@csrf_exempt
def decrypt_aes(request):
    hex_key = request.POST.get('key')
    hex_iv = request.POST.get('iv')
    encrypted_text = request.POST.get('encrypted_text')

    # Convert the hexadecimal key to bytes
    try:
        key = binascii.unhexlify(hex_key)
    except binascii.Error:
        return JsonResponse({'error': 'Invalid AES key. Key must be a 64-character hexadecimal string.'},
                            status=400)

    # Validate the key length for AES-256
    if len(key) != 32:
        return JsonResponse({'error': 'Incorrect AES key length. Key must be 32 bytes (256 bits) long.'},
                            status=400)

    # Convert the hexadecimal IV to bytes
    try:
        iv = binascii.unhexlify(hex_iv)
    except binascii.Error:
        return JsonResponse({'error': 'Invalid IV. IV must be a 32-character hexadecimal string.'},
                            status=400)

    # Validate the IV length
    if len(iv) != AES.block_size:
        return JsonResponse({'error': 'Incorrect IV length. IV must be 16 bytes (128 bits) long.'},
                            status=400)

    # Decode the encrypted text from base64
    try:
        encrypted_text_bytes = base64.b64decode(encrypted_text)
    except binascii.Error:
        return JsonResponse({'error': 'Invalid encrypted text. Encrypted text must be a base64-encoded string.'},
                            status=400)

    # Decrypt the text
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_text = unpad(cipher.decrypt(encrypted_text_bytes)).decode('utf-8')
    except (ValueError, KeyError, binascii.Error) as e:
        return JsonResponse({'error': 'Decryption failed. ' + str(e)},
                            status=400)

    return JsonResponse({'decrypted_text': decrypted_text})


@csrf_exempt
def decrypt_rsa(request):
    private_key_string = request.POST.get('private_key')
    encrypted_text = base64.b64decode(request.POST.get('encrypted_text'))

    # Check if the private key is provided
    if not private_key_string:
        return JsonResponse({'error': 'No public key provided. Please provide a valid RSA private key.'}, status=400)

    # Import the user-provided private key
    try:
        rsa_key = RSA.import_key(private_key_string)
    except (ValueError, IndexError):
        return JsonResponse({'error': 'Invalid private key format. Please provide a private key in the correct format.'},
                            status=400)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_text = cipher.decrypt(encrypted_text).decode('utf-8')
    return JsonResponse({'decrypted_text': decrypted_text})

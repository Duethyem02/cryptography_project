$(document).ready(function () {
    $('#aesBtn').click()
});

// JavaScript to toggle forms
$('#aesBtn').click(function () {
    $('#aesForm').toggle();
    $('#rsaBtn').removeClass("active")
    $('#aesBtn').addClass("active")
    $('#rsaForm').hide();
});
$('#rsaBtn').click(function () {
    $('#rsaBtn').addClass("active")
    $('#aesBtn').removeClass("active")
    $('#rsaForm').toggle();
    $('#aesForm').hide();
});

function decryptAES() {
    const key = $('#aesDecryptKey').val();
    const iv = $('#aesDecryptIV').val();
    const encryptedText = $('#aesEncryptedText').val();
    
    // Check if the key length is 64 characters (32 bytes)
    if (key.length !== 64) {
        alert('The AES key must be 32 bytes in hexadecimal format.(64 characters)');
        return;
    }

    // Check if the IV length is 32 characters (16 bytes) if provided
    if (iv && iv.length !== 32) {
        alert('The Initialization Vector (IV) must be 16 bytes in hexadecimal format (32 characters).');
        return;
    }

    if (!encryptedText) {
        alert("Please provide text for decryption.")
        return
    }

    $.ajax({
        url: decryptAesUrl,
        type: 'POST',
        data: {
            'key': key,
            'iv': iv,
            'encrypted_text': encryptedText,
            'csrfmiddlewaretoken': csrfToken
        },
        success: function (response) {
            $('#aesDecryptOutput').html('Decrypted Text: ' + response.decrypted_text);
        },
        error: function (xhr) {
            if (xhr.status === 500) {
                $('#aesDecryptOutput').html("Something went wrong");
            } else {
                $('#aesDecryptOutput').html(xhr.responseJSON.error);
            }
        }
    });
}

function decryptRSA() {
    const privateKey = $('#rsaDecryptPrivateKey').val();
    const encryptedText = $('#rsaEncryptedText').val();

    // Check if the private key is provided
    if (!privateKey.trim()) {
        alert('Please provide an RSA private key.');
        return;
    }

    // Check if the private key starts with the correct header
    if (!privateKey.trim().startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
        alert('Invalid private key format. The key must start with "-----BEGIN RSA PRIVATE KEY-----".');
        return;
    }

    // Check if the private key ends with the correct footer
    if (!privateKey.trim().endsWith('-----END RSA PRIVATE KEY-----')) {
        alert('Invalid private key format. The key must end with "-----END RSA PRIVATE KEY-----".');
        return;
    }

    if (!encryptedText) {
        alert("Please provide text for decryption.")
        return
    }
    // Add client-side validation if needed

    $.ajax({
        url: decryptRsaUrl,
        type: 'POST',
        data: {
            'private_key': privateKey,
            'encrypted_text': encryptedText,
            'csrfmiddlewaretoken': csrfToken
        },
        success: function(response) {
            $('#rsaDecryptOutput').html('Decrypted Text: ' + response.decrypted_text);
        },
        error: function (xhr) {
            if (xhr.status === 500) {
                $('#rsaDecryptOutput').html("Something went wrong");
            } else {
                $('#rsaDecryptOutput').html(xhr.responseJSON.error);
            }
        }
    });
}

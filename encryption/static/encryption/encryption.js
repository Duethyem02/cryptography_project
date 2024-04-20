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





function generateAESKey() {
    // Generate a random 256-bit key and display it in the AES key input field
    const randomKey = CryptoJS.lib.WordArray.random(32).toString(CryptoJS.enc.Hex);
    $('#aesKey').val(randomKey);
}
// JavaScript functions to call Django back-end for encryption
function encryptAES() {
    const key = $('#aesKey').val();
    const iv = $('#aesIV').val();
    const text = $('#aesText').val();

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

    if (!text) {
        alert("Please provide text for encryption.")
        return
    }

    $.ajax({
        url: encryptAesUrl,
        type: 'POST',
        data: {
            'key': key,
            'iv': iv,
            'text': text,
            'csrfmiddlewaretoken': csrfToken
        },
        success: function (response) {
            $('#aesOutput').html('Encrypted Text: ' + response.encrypted_text + '<br>Initialization Vector: ' + response.iv);
        },
        error: function (xhr) {
            if (xhr.status === 500) {
               $('#aesOutput').html("Something went wrong")
            }
            else {
               $('#aesOutput').html(xhr.responseJSON.error)
            }
        }
    });
}

function encryptRSA() {
    const publicKey = $('#rsaPublicKey').val();
    const text = $('#rsaText').val();

    // Check if the public key is provided
    if (!publicKey.trim()) {
        alert('Please provide an RSA public key.');
        return;
    }

    // Check if the public key starts with the correct header
    if (!publicKey.trim().startsWith('-----BEGIN PUBLIC KEY-----')) {
        alert('Invalid public key format. The key must start with "-----BEGIN PUBLIC KEY-----".');
        return;
    }

    // Check if the public key ends with the correct footer
    if (!publicKey.trim().endsWith('-----END PUBLIC KEY-----')) {
        alert('Invalid public key format. The key must end with "-----END PUBLIC KEY-----".');
        return;
    }

    if (!text) {
        alert("Please provide text for encryption.")
        return
    }

    $.ajax({
        url: encryptRsaUrl,
        type: 'POST',
        data: {
            'public_key': publicKey,
            'text': text,
            'csrfmiddlewaretoken': csrfToken
        },
        success: function(response) {
            $('#rsaOutput').html('Encrypted Text: ' + response.encrypted_text);
        },
        error: function (xhr) {
            if (xhr.status === 500) {
               $('#rsaOutput').html("Something went wrong")
            }
            else {
               $('#rsaOutput').html(xhr.responseJSON.error)
            }
        }
    });
}


function generateRSAKeys() {
    $.ajax({
        url: generateRsaKeyUrl,
        type: 'GET',
        success: function(response) {
            const privateKeyBlob = new Blob([response.private_key], {type: 'text/plain'});
            const publicKeyBlob = new Blob([response.public_key], {type: 'text/plain'});
            const privateKeyUrl = URL.createObjectURL(privateKeyBlob);
            const publicKeyUrl = URL.createObjectURL(publicKeyBlob);

            // Create download links for the keys
            const downloadLinkPrivate = document.createElement('a');
            downloadLinkPrivate.href = privateKeyUrl;
            downloadLinkPrivate.download = 'private_key.pem';
            downloadLinkPrivate.click();

            const downloadLinkPublic = document.createElement('a');
            downloadLinkPublic.href = publicKeyUrl;
            downloadLinkPublic.download = 'public_key.pem';
            downloadLinkPublic.click();
        }
    });
}




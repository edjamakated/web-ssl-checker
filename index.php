<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $domain = $_POST['domain'];
    $context = stream_context_create(['ssl' => ['capture_peer_cert' => true]]);
    $stream = @stream_socket_client('ssl://' . $domain . ':443', $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);

    if (!$stream) {
        echo json_encode(["status" => "error", "message" => "Unable to connect"]);
        exit();
    }

    $certificate = stream_context_get_params($stream)['options']['ssl']['peer_certificate'];
    $certinfo = openssl_x509_parse($certificate);

    if (time() < $certinfo['validFrom_time_t'] || time() > $certinfo['validTo_time_t']) {
        echo json_encode(["status" => "expired", "message" => "Expired"]);
    } else {
        echo json_encode(["status" => "valid", "message" => "Valid"]);
    }
    exit();
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL Certificate Checker</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.min.css">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        body {
            display: flex;
            flex-direction: column;
            align-items: center;
            font-family: Arial, sans-serif;
        }

        #ssl-form {
            display: flex;
            flex-direction: column;
            width: 100%;
            max-width: 600px;
            margin-bottom: 20px;
        }

        textarea {
            resize: vertical;
        }

        #result {
            font-family: monospace;
            width: 100%;
            max-width: 600px;
        }

        .domain-result {
            margin-bottom: 10px;
        }
    </style>
</head>

<body>
    <h1>SSL Certificate Checker</h1>
    <form id="ssl-form">
        <label for="domain-list">Enter domain names separated by comma:</label>
        <textarea id="domain-list" name="domain-list" rows="10" cols="50"></textarea>
        <input type="submit" value="Check SSL Certificates">
    </form>
    <div id="result"></div>
    <script>
        $(function() {
            $('#ssl-form').submit(function(event) {
                event.preventDefault();
                // Use a regular expression to split the input by comma or newline
                const domains = $('#domain-list').val().split(/[,|\n]/);
                const result = $('#result');
                result.empty();

                domains.forEach(function(domain) {
                    const trimmedDomain = domain.trim();
                    if (trimmedDomain) {
                        const domainResult = $('<div>').addClass('domain-result').appendTo(result);
                        domainResult.text(`Checking ${trimmedDomain}...`);

                        $.ajax({
                            url: window.location.href, // Set the URL to the current page
                            type: 'POST',
                            data: {
                                domain: trimmedDomain
                            },
                            dataType: 'json', // Expect a JSON response
                            success: function(response) {
                                domainResult.text(`${trimmedDomain}: ${response.message}`);
                            },
                            error: function() {
                                domainResult.text(`${trimmedDomain}: Error occurred while checking SSL certificate`);
                            }
                        });
                    }
                });
            });
        });
    </script>
</body>

</html>

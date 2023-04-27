<!DOCTYPE html>
<html>
<head>
    <title>SSL Certificate Checker</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        #result {
            font-family: monospace;
        }
          .domain-result {
        margin-bottom: 10px;
    }
</style>
</head>
<body>
    <h1>SSL Certificate Checker</h1>
    <form id="ssl-form">
        <label for="domain-list">Enter domain names separated by comma:</label><br>
        <textarea id="domain-list" name="domain-list" rows="10" cols="50"></textarea><br><br>
        <input type="submit" value="Check SSL Certificates">
    </form>
    <br>
    <div id="result"></div>
  <script>
    $(function () {
        $('#ssl-form').submit(function (event) {
            event.preventDefault();
            let domains = $('#domain-list').val().split(',');
            let result = $('#result');
            result.empty();

            domains.forEach(function (domain) {
                domain = domain.trim();
                if (domain) {
                    let domainResult = $('<div>').addClass('domain-result').appendTo(result);
                    domainResult.text('Checking ' + domain + '...');

                    $.ajax({
                        url: 'ssl-checker.php',
                        type: 'POST',
                        data: { domain: domain },
                        success: function (response) {
                            domainResult.text(domain + ': ' + response);
                        },
                        error: function () {
                            domainResult.text(domain + ': Error occurred while checking SSL certificate');
                        }
                    });
                }
            });
        });
    });
</script>
</body>
</html>
<!-- Create a separate PHP file named "ssl-checker.php" -->
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $domain = $_POST['domain'];
    $context = stream_context_create(['ssl' => ['capture_peer_cert' => true]]);
    $stream = @stream_socket_client('ssl://' . $domain . ':443', $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);

    if (!$stream) {
        echo "Unable to connect";
        exit();
    }

    $certificate = stream_context_get_params($stream)['options']['ssl']['peer_certificate'];
    $certinfo = openssl_x509_parse($certificate);

    if (time() < $certinfo['validFrom_time_t'] || time() > $certinfo['validTo_time_t']) {
        echo "Expired";
    } else {
        echo "Valid";
    }
    exit();
}
?>

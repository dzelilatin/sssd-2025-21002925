<?php
$response = file_get_contents('https://hcaptcha.com/siteverify', false,
    stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => 'Content-type: application/x-www-form-urlencoded',
            'content' => http_build_query([
                'secret' => HCAPTCHA_SERVER_SECRET,
                'response' => $_POST['h-captcha-response']
            ])
        ]
    ])
);

$responseData = json_decode($response);

if ($responseData->success) {
   // your success code goes here
   echo "You passed the captcha!";
} else {
   // return an error to the user; they did not pass
   echo "You did NOT pass the captcha!";
}
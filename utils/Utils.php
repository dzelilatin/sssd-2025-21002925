<?php
require_once __DIR__ . '/../config_default.php';
require_once __DIR__ . '/../vendor/autoload.php';

use Google\Client;

class Utils {
    public static function getGoogleClient() {
        $client = new Client();
        $client->setClientId(GOOGLE_CLIENT_ID);
        $client->setClientSecret(GOOGLE_CLIENT_SECRET);
        $client->setRedirectUri(GOOGLE_REDIRECT_URI);
        $client->addScope('email');
        $client->addScope('profile');
        $client->setHttpClient(new \GuzzleHttp\Client([
            'verify' => false
        ]));
        return $client;
    }
} 
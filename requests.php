<?php

$response = new CurlUtil();
echo $response->getRequest();
echo $response->postRequestWithJSON();
echo $response->deleteRequest();
echo $response->putRequest();
echo $response->patchRequest();
echo $response->putRequestWithJsonAndHeaders();

class CurlUtil {

    // 1. GET Request with Custom Headers
    // Add custom headers X-Custom-Header: Value1 and Authorization: Bearer YourToken.

    function getRequest() {
        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => 'https://eoei4rn90qbz55y.m.pipedream.net/data',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => 'GET',
            CURLOPT_HTTPHEADER => array(
                'X-Custom-Header: Value1',
                'Authorization: Bearer YourToken',
            ),
        ));

        $response = curl_exec($curl);
        curl_close($curl);
        return $response;
    }

    // 2. POST Request with JSON Data
    // The request should include JSON data {"name":"John", "email":"john@example.com"}.
    // Set the appropriate Content-Type header.

    function postRequestWithJSON() {
        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => 'https://eoei4rn90qbz55y.m.pipedream.net/users',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => json_encode(["name" => "John", "email" => "john@example.com"]),
            CURLOPT_HTTPHEADER => array(
                'Content-Type: application/json',
            ),
        ));

        $response = curl_exec($curl);
        curl_close($curl);
        return $response;
    }

    // 3. DELETE Request
    // Ensure you handle the response to check if the deletion was successful.

    function deleteRequest() {

        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => 'https://eoei4rn90qbz55y.m.pipedream.net/users/123',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => 'DELETE',
            CURLOPT_HTTPHEADER => array(
                'Content-Type: application/json',
                'Accept: application/json',
            ),
        ));

        $response = curl_exec($curl);
        curl_close($curl);
        return $response;
    }

    // 4. PUT Request with Form Data
    // Update the user's data by sending form-encoded data name=Jane & email=jane@example.com.

    function putRequest() {
        $postData = http_build_query(["name" => "Jane", "email" => "jane@example.com"]);
        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => 'https://eoei4rn90qbz55y.m.pipedream.net/users/123',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => 'PUT',
            CURLOPT_POSTFIELDS => $postData,
            CURLOPT_HTTPHEADER => array(
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json'
            ),
        ));

        $response = curl_exec($curl);
        curl_close($curl);
        return $response;
    }


    // 5. PATCH Request with Custom User Agent
    // Update the user's status to active. Include a custom user agent MyCustomUserAgent/1.0.

    function patchRequest() {

        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => 'https://eoei4rn90qbz55y.m.pipedream.net/users/123',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => 'PATCH',
            CURLOPT_POSTFIELDS => json_encode(["status" => "active"]),
            CURLOPT_HTTPHEADER => array(
                'User-Agent: MyCustomUserAgent/1.0',
                'Content-Type: application/json'
            ),
        ));

        $response = curl_exec($curl);
        curl_close($curl);
        return $response;
    }

    // 6. PUT Request with JSON Data and Custom Headers
    //  Update settings with JSON data {"theme":"dark", "notifications":"enabled"}.
    //  Include a custom header X-Request-ID: 789.

    function putRequestWithJsonAndHeaders() {
        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => 'https://eoei4rn90qbz55y.m.pipedream.net/settings/456',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => 'PUT',
            CURLOPT_POSTFIELDS => json_encode(["theme" => "dark", "notifications" => "enabled"]),
            CURLOPT_HTTPHEADER => array(
                'X-Request-ID: 789',
                'Content-Type: application/json'
            ),
        ));

        $response = curl_exec($curl);
        curl_close($curl);
        return $response;
    }
}
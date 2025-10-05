<?php
require("vendor/autoload.php");

$openapi = \OpenApi\Generator::scan(['/Applications/XAMPP/xamppfiles/htdocs/sssd-2025-21002925/api/']);
/** ili staviti pod komentar prvu liniju:, a drugu uncomment. 
 * // $openapi = \OpenApi\Generator::scan(['/Applications/XAMPP/xamppfiles/htdocs/sssd-2025-21002925/api']);
 * $openapi = \OpenApi\Generator::scan([__DIR__ . '/api']);
 * works both ways, probala sam
 */

header('Content-Type: application/json');
echo $openapi->toJson();

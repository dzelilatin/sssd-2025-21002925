<?php
// Include the Composer autoloader
require_once __DIR__ . '/vendor/autoload.php';

// Include the FlightPHP framework
require_once __DIR__ . '/vendor/mikecao/flight/flight/Flight.php';

// Include the database configuration
require_once __DIR__ . '/config_default.php';

// Include the database connection
require_once __DIR__ . '/database.php';

// Include the API routes
require_once __DIR__ . '/api/index.php';

// Start the FlightPHP framework
Flight::start(); 
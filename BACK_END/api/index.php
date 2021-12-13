<?php
use Slim\Factory\AppFactory;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Tuupola\Middleware\JwtAuthentication as JwtAuthentication;

require './vendor/autoload.php';
require './src/JwtHandler.php';

$app = AppFactory::create();

// Config authenticator Tuupola
$app->add(new JwtAuthentication([
    "secret" => Get_JWT_Secret(),
    "attribute" => "token",
    "header" => "Authorization",
    "regexp" => "/Bearer\s+(.*)$/i",
    "secure" => false,
    "algorithm" => ["HS512"],

    "path" => ["/api"],
    "ignore" => ["/api/login"],
    "error" => function ($response, $arguments) {
        $data = array('ERREUR' => 'Connexion', 'ERREUR' => 'JWT Non valide');
        $response = $response->withStatus(401);
        return $response->withHeader("Content-Type", "application/json")->getBody()->write(json_encode($data));
    }
]));

$app->get('/api/auth/{username}', function (Request $request, Response $response, $args) {
    $username = $args['username'];
    if ($username) {
        $data["username"] = $username;
        $response = addHeaders($response);
        $response = createJWT($response, $username);
        $response->getBody()->write(json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
    } else {
        $response = $response->withStatus(401);
    }

    return $response;
});

$app->post('/api/login', function (Request $request, Response $response, $args) {
    $isRequestValid = true;

    $body = $request->getParsedBody();
    $username = $body['username'] ?? "";
    $password = $body['password'] ?? "";

    $isRequestValid = ($password == "");

    if ($isRequestValid) {
        $data["username"] = $username;
        $response = addHeaders($response);
        $response = createJWT($response, $username);
        $response->getBody()->write(json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
    } else {
        $response = $response->withStatus(401);
    }
    return $response;
});

function addHeaders($response) {
    $response = $response->withHeader("Content-Type", "application/json")
        ->withHeader("Access-Control-Allow-Origin", "https://tp05-allemann-louis.herokuapp.com")
        ->withHeader("Access-Control-Allow-Headers", "Content-Type, Authorization")
        ->withHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        ->withHeader("Access-Control-Expose-Headers", "Authorization");

    return $response;
}

function createJWT($response, $login) {
    $issuedAt = time();
    $expirationTime = $issuedAt + 600; // + 10 minutes
    $payload = array(
      'username' => $username,
      'iat' => $issuedAt,
      'exp' => $expirationTime
    );
  
    $token_jwt = JWT::encode($payload, JWT_SECRET, "HS256");
    $response = $response->withHeader("Authorization", "Bearer {$token_jwt}");
    return $response;
}

// Run app
$app->run();

?>
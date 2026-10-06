<?php
// scanX fixture: intentionally vulnerable. FAKE data only.
require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/config.php';

$conn = db_connect();

// SQL injection: user input concatenated into a query (CWE-89)
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);

// Reflected XSS: user input echoed without escaping (CWE-79)
echo "<h1>Hello " . $_GET['name'] . "</h1>";

// OS command injection (CWE-78)
$host = $_POST['host'];
system("ping -c 1 " . $host);

// Local file inclusion (CWE-98)
include $_GET['page'] . '.php';

// Insecure deserialization (CWE-502)
$prefs = unserialize($_COOKIE['prefs']);

// Open redirect (CWE-601)
header("Location: " . $_GET['next']);

// Code injection (CWE-95)
eval($_REQUEST['code']);

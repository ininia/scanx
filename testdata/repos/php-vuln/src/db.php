<?php
// scanX fixture: FAKE credentials only.
function db_connect()
{
    return mysqli_connect('localhost', 'app', DB_PASSWORD, 'app');
}

function find_user_by_name($conn, $name)
{
    // SQL injection through a function parameter fed by the request
    return mysqli_query($conn, "SELECT * FROM users WHERE name = '$name'");
}

function weak_password_hash($password)
{
    // Weak hashing for passwords (CWE-328)
    return md5($password);
}

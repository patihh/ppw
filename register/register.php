<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "data";

$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection Error: " . $conn->connect_error);
}

$nama = isset($_POST['nama']) ? $_POST['nama'] : '';
$email = isset($_POST['email']) ? $_POST['email'] : '';
$password = isset($_POST['password']) ? $_POST['password'] : '';

if (!empty($nama) && !empty($email) && !empty($password)) {
    $stmt = $conn->prepare("SELECT email FROM user WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        echo "<script>alert('Email is already registered. Please use another email!');</script>";
    } else {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("INSERT INTO user (nama, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $nama, $email, $hashed_password);
        
        if ($stmt->execute()) {
            echo "<script>alert('Account successfully registered. Please login to your account!'); window.location.href='../login/login.php';</script>";
        } else {
            echo "Error: " . $stmt->error;
        }
    }
    $stmt->close();
}
$conn->close();
?>

<!DOCTYPE html>
<head>
    <link rel="icon" type="image/x-icon" href="icon.png">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>E-Commerce | Register</title>
    <link rel="stylesheet" href="style_register.css">
</head>
<body>
   
    <header>
        <div class="header-left">
            <a href="">
                <img src="logo.jpg" alt="e-commerce logo">
            </a>
        </div>
        <div class="header-center"></div>
        <div class="header-right">
            <a href="../login/login.php" class="btn-login">Login</a>
            <a href="" class="btn-register">Register</a>
        </div>
    </header>

    <div class="login-container">
        <div class="login-box">
            <h2>Register</h2>
            <form action="register.php" method="POST">
                <div class="input-group">
                    <label for="username">Username</label>
                    <input type="text" id="nama" name="nama" placeholder="Enter your username" required>
                </div>
                <div class="input-group">
                    <label for="email">Email</label>
                    <input type="email" id="email" name="email" placeholder="Enter your email" required>
                </div>
                <div class="input-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" placeholder="Enter your password" required>
                </div>
                <div class="input-group">
                    <button type="submit" name="register" class="btn-register">Register</button>
                </div>
                <div class="input-group">
                    <p class="signup-text">Already have an account? <a href="../login/login.php">Log In</a></p>
                </div>
            </form>
        </div>
    </div>

    <footer>
        <p>E-Commerce © 2024</p>
    </footer>
</body>
</html>
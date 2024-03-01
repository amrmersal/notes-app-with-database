<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Note Taking App</title>
</head>
<body>
<?php
session_start();

// DB LINK
$host = '127.0.0.1:3306';
$dbname = 'notes_app';
$username = 'amrmersal';
$password = '2022004';

try {
    
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}
function sanitize_input($input) {
    return htmlspecialchars(strip_tags(trim($input)));
}
function validate_email($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}
function validate_password($password) {
    return strlen($password) >= 6;
}
function authenticate_user($email, $password, $pdo) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($user && password_verify($password, $user['password'])) {
        return $user;
    }
    return false;
}
function register_user($email, $password, $pdo) {
    if (validate_email($email) && validate_password($password)) {
        // Hashing pass
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        // sendinh to DB
        $stmt = $pdo->prepare("INSERT INTO users (email, password) VALUES (:email, :password)");
        $stmt->execute(['email' => $email, 'password' => $hashed_password]);
        return true;
    }
    return false;
}
function save_note($user_id, $note, $pdo) {
    $stmt = $pdo->prepare("INSERT INTO notes (user_id, note) VALUES (:user_id, :note)");
    $stmt->execute(['user_id' => $user_id, 'note' => $note]);
}

function get_saved_notes($user_id, $pdo) {
    $stmt = $pdo->prepare("SELECT id, note FROM notes WHERE user_id = :user_id");
    $stmt->execute(['user_id' => $user_id]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function delete_note($note_id, $pdo) {
    $stmt = $pdo->prepare("DELETE FROM notes WHERE id = :note_id");
    $stmt->execute(['note_id' => $note_id]);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['login'])) {
        $email = sanitize_input($_POST['email']);
        $password = sanitize_input($_POST['password']);

        $user = authenticate_user($email, $password, $pdo);
        if ($user) {
            $_SESSION['user_id'] = $user['id'];
            echo "Login successful";
        } else {
            echo "Invalid mail or password";
        }
    }
    if (isset($_POST['logout'])) {
        unset($_SESSION['user_id']);
        echo "Logged out";
    }
    if (isset($_POST['signup'])) {
        $email = sanitize_input($_POST['email']);
        $password = sanitize_input($_POST['password']);

        if (register_user($email, $password, $pdo)) {
            echo "Signed up successfully";
        } else {
            echo "Invalid mail or password";
        }
    }
    if (isset($_POST['save_note'])) {
        if (isset($_SESSION['user_id'])) {
            $note = sanitize_input($_POST['note_content']);
            $user_id = $_SESSION['user_id'];
            save_note($user_id, $note, $pdo);
            echo "Note saved";
        } else {
            echo "You must log in to save note";
        }
    }
    if (isset($_POST['delete_note'])) {
        $note_id = $_POST['note_id'];
        delete_note($note_id, $pdo);
        echo "Note deleted";
    }
}
 
?>   
<div id="choiceContainer" <?php if(isset($_SESSION['user_id'])) { echo 'style="display: none;"'; } ?>>
    <h2>Choose an option</h2>
    <button onclick="showLogin()">Login</button>
    <button onclick="showSignup()">Sign Up</button>
</div>

<div id="loginContainer" style="display: none;">
    <h2>Login</h2>
    <form method="post">
        <label for="email">Email:</label><br>
        <input type="email" id="email" name="email" placeholder="Email" required><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password" placeholder="Password" required><br>
        <input type="submit" name="login" value="Login">
    </form>
</div>

<div id="signupContainer" style="display: none;">
    <h2>Sign Up</h2>
    <form method="post">
        <label for="email">Email:</label><br>
        <input type="email" id="email" name="email" placeholder="Email" required><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password" placeholder="Password" required><br>
        <input type="submit" name="signup" value="Sign Up">
    </form>
</div>

<div id="noteContainer" <?php if(!isset($_SESSION['user_id'])) { echo 'style="display: none;"'; } ?>>
    <h2>Type your note</h2>
    <form method="post">
        <label for="note_content">Your Note:</label><br>
        <textarea id="note_content" name="note_content" placeholder="Enter your note here" ></textarea><br>
        <input type="submit" name="save_note" value="Save Note">
    </form>
    <form method="post">
        <input type="submit" name="logout" value="Logout">
    </form>
</div>

<div id="savedNotes">
    <?php
    if (isset($_SESSION['user_id'])) {
        $user_id = $_SESSION['user_id'];
        $notes = get_saved_notes($user_id, $pdo);
        if ($notes) {
            echo '<h3>Saved Notes:-</h3>';
            foreach ($notes as $note) {
                echo '<p>Note: ' . $note['note'] . ' <form method="post" style="display:inline;">
                <input type="hidden" name="note_id" value="' . $note['id'] . '">
                <input type="submit" name="delete_note" value="Delete"></form></p>';
            }
        } else {
            echo '<p>No notes found</p>';
        }
    }
    ?>
</div>

<script>
    function showLogin() {
        document.getElementById('choiceContainer').style.display = 'none';
        document.getElementById('loginContainer').style.display = 'block';
    }

    function showSignup() {
        document.getElementById('choiceContainer').style.display = 'none';
        document.getElementById('signupContainer').style.display = 'block';
    }
</script>

</body>
</html>

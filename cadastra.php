<?php

$servidor = "localhost";
$user = "root";
$password = ""; // Lembre-se de definir sua senha corretamente aqui
$bd = "Cadastro";

$conn = new mysqli($servidor, $user, $password, $bd);

if ($conn->connect_error) {
    die("Erro de conexão: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $usuario = $_POST["usuario"];
    $senha = $_POST["senha"];
    $confirmasenha = $_POST["confirmarsenha"];

    echo "<p>Usuário: $usuario</p>";
    echo "<p>Senha: $senha</p>";
    echo "<p>Confirmação de Senha: $confirmasenha</p>";

    if ($senha !== $confirmasenha) {
        echo "As senhas não coincidem!";
    } else {
        // Hash da senha
        $hashsenha = password_hash($senha, PASSWORD_BCRYPT);
        
        echo "<p>Hash da Senha: $hashsenha</p>";

        // Inserção no banco de dados
        $sql = "INSERT INTO usuario (usuario, senha) VALUES (?, ?)";
        $stmt = $conn->prepare($sql);

        if (!$stmt) {
            die("Erro na preparação da declaração: " . $conn->error);
        }

        $stmt->bind_param("ss", $usuario, $hashsenha);

        if (!$stmt->execute()) {
            die("Erro ao executar a declaração: " . $stmt->error);
        } else {
            echo "Cadastro realizado!";
        }
    }
}

$conn->close();
?>

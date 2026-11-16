<?php
declare(strict_types=1);
require __DIR__ . '/../src/lib.php';
session_boot();

$err = '';
if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: ./');
    exit;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    if (hash_equals((string)cfg()['app_password'], (string)$_POST['password'])) {
        session_regenerate_id(true);
        $_SESSION['auth'] = true;
        header('Location: ./');
        exit;
    }
    $err = 'Password errata';
}
$logged = is_logged();
$h = fn(string $s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
?><!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="theme-color" content="#0d6efd">
  <title>EG Auto · Posizione</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" rel="stylesheet">
  <link href="assets/app.css" rel="stylesheet">
</head>
<body class="bg-light">
<nav class="navbar navbar-dark bg-primary sticky-top shadow-sm">
  <div class="container-fluid">
    <span class="navbar-brand d-flex align-items-center gap-2 mb-0">
      <span class="material-icons-round">directions_car</span> EG Auto · Posizione
    </span>
    <?php if ($logged): ?>
      <a class="btn btn-sm btn-outline-light" href="?logout=1" title="Esci">
        <span class="material-icons-round align-middle">logout</span></a>
    <?php endif; ?>
  </div>
</nav>

<main class="container py-3" style="max-width:720px">
<?php if (!$logged): ?>
  <form method="post" class="card shadow-sm border-0 mt-4">
    <div class="card-body">
      <h5 class="card-title d-flex align-items-center gap-2">
        <span class="material-icons-round text-primary">lock</span> Accesso</h5>
      <?php if ($err): ?><div class="alert alert-danger py-2"><?= $h($err) ?></div><?php endif; ?>
      <input type="password" name="password" class="form-control form-control-lg mb-3"
             placeholder="Password" autocomplete="current-password" required autofocus>
      <button class="btn btn-primary btn-lg w-100">Entra</button>
    </div>
  </form>
<?php else: ?>
  <div class="card shadow-sm border-0 mb-3">
    <div class="card-body">
      <label for="plate" class="form-label fw-semibold">Targa</label>
      <div class="input-group input-group-lg">
        <span class="input-group-text"><span class="material-icons-round">pin</span></span>
        <input id="plate" class="form-control text-uppercase" maxlength="10"
               placeholder="AB123CD" autocomplete="off" autocapitalize="characters" inputmode="text">
        <button id="btnSearch" class="btn btn-primary" type="button" title="Cerca">
          <span class="material-icons-round align-middle">search</span></button>
      </div>
      <div id="msg" class="mt-3"></div>
    </div>
  </div>

  <div id="card" class="card shadow-sm border-0 mb-3 d-none">
    <div class="card-body">
      <div class="d-flex justify-content-between align-items-start">
        <div>
          <h4 id="vPlate" class="mb-0 fw-bold"></h4>
          <div id="vInfo" class="text-muted"></div>
        </div>
        <span id="vBadge" class="badge rounded-pill"></span>
      </div>
      <div id="vCoords" class="mt-2 small text-muted"></div>
      <div class="d-grid gap-2 mt-3">
        <button id="btnGps" class="btn btn-success btn-lg" type="button">
          <span class="material-icons-round align-middle">my_location</span>
          Salva posizione di questo dispositivo</button>
        <a id="btnNav" class="btn btn-outline-primary d-none" target="_blank" rel="noopener">
          <span class="material-icons-round align-middle">navigation</span> Apri in Google Maps</a>
      </div>
    </div>
  </div>

  <div id="map" class="shadow-sm rounded d-none"></div>
<?php endif; ?>
</main>

<?php if ($logged): ?>
<script>
  window.APP = { csrf: <?= json_encode(csrf_token()) ?> };
</script>
<script src="assets/app.js"></script>
<script async defer
  src="https://maps.googleapis.com/maps/api/js?key=<?= $h(cfg()['google_maps_key']) ?>&callback=initMap&loading=async"></script>
<?php endif; ?>
</body>
</html>

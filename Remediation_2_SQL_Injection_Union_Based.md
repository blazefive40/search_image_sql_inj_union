# REMÉDIATION - SQL Injection Union-Based (Image Search)

## 📋 Informations sur la vulnérabilité

- **Type**: SQL Injection Union-Based
- **Page affectée**: `http://192.168.10.146/?page=searchimg`
- **Paramètre vulnérable**: `id`
- **Niveau de criticité**: 🔴 CRITIQUE
- **Impact**: Extraction de données de n'importe quelle table, accès à information_schema

---

## 🔍 Description de la faille

La page de recherche d'images permet de rechercher une image par son numéro. Le paramètre `id` est injecté directement dans la requête SQL, permettant l'utilisation de UNION SELECT pour extraire des données de n'importe quelle table de la base de données.

### Exploitation réussie

```sql
-- Requête normale
id=1
Résultat: Affiche l'image #1 (Nsa)

-- Détection du nombre de colonnes
id=1 UNION SELECT 1,2
Résultat: 2 colonnes détectées

-- Extraction des données sensibles
id=1 UNION SELECT title,comment FROM Member_images.list_images
Résultat: Extraction de hash MD5 depuis les commentaires
```

---

## 💻 Code vulnérable (AVANT)

```php
<?php
// ❌ CODE VULNÉRABLE - NE PAS UTILISER

// Récupération du paramètre sans validation
$id = $_GET['id'];

// Construction de la requête avec concaténation
$query = "SELECT id, title, url
          FROM list_images
          WHERE id = " . $id;

// Exécution
$result = mysqli_query($conn, $query);

// Affichage des résultats
if ($row = mysqli_fetch_assoc($result)) {
    echo "<pre>";
    echo "ID: " . $row['id'] . " <br>";
    echo "Title: " . $row['title'] . "<br>";
    echo "Url : " . $row['url'];
    echo "</pre>";
}
?>
```

### Problèmes identifiés:
1. ❌ Aucune validation du paramètre `id`
2. ❌ Concaténation directe sans quotes (pire que avec quotes!)
3. ❌ Pas de typage strict
4. ❌ Possibilité d'utiliser UNION SELECT
5. ❌ Accès possible à information_schema
6. ❌ Pas de limitation du nombre de résultats

---

## ✅ Code sécurisé (APRÈS)

### Solution complète avec PDO

```php
<?php
// ✅ CODE SÉCURISÉ - RECOMMANDÉ

class ImageSearch {
    private $pdo;

    public function __construct($pdo) {
        $this->pdo = $pdo;
    }

    /**
     * Validation stricte de l'ID d'image
     */
    private function validateImageId($id) {
        // Vérifier que c'est un entier positif
        if (!filter_var($id, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => 9999]
        ])) {
            return false;
        }
        return (int)$id;
    }

    /**
     * Recherche sécurisée d'une image
     */
    public function searchImage($imageId) {
        try {
            // Validation de l'ID
            $validId = $this->validateImageId($imageId);
            if ($validId === false) {
                throw new InvalidArgumentException("ID d'image invalide");
            }

            // Requête préparée avec typage strict
            $stmt = $this->pdo->prepare("
                SELECT id, title, url
                FROM list_images
                WHERE id = :id
                LIMIT 1
            ");

            // Liaison avec type INT
            $stmt->bindParam(':id', $validId, PDO::PARAM_INT);
            $stmt->execute();

            // Récupération du résultat
            $image = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$image) {
                return [
                    'success' => false,
                    'message' => 'Image non trouvée'
                ];
            }

            return [
                'success' => true,
                'data' => [
                    'id' => (int)$image['id'],
                    'title' => htmlspecialchars($image['title'], ENT_QUOTES, 'UTF-8'),
                    'url' => htmlspecialchars($image['url'], ENT_QUOTES, 'UTF-8')
                ]
            ];

        } catch (InvalidArgumentException $e) {
            return [
                'success' => false,
                'message' => $e->getMessage()
            ];
        } catch (PDOException $e) {
            // Logger l'erreur (ne jamais l'afficher)
            error_log("Database error in searchImage: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Une erreur est survenue'
            ];
        }
    }
}

// Utilisation
try {
    $pdo = new PDO(
        "mysql:host=localhost;dbname=Member_images;charset=utf8mb4",
        "webapp_user",
        "secure_password",
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
        ]
    );

    $imageSearch = new ImageSearch($pdo);
    $result = $imageSearch->searchImage($_GET['id'] ?? null);

    if ($result['success']) {
        $data = $result['data'];
        echo "<pre>";
        echo "ID: " . $data['id'] . " <br>";
        echo "Title: " . $data['title'] . "<br>";
        echo "Url : " . $data['url'];
        echo "</pre>";
    } else {
        echo "<p>" . htmlspecialchars($result['message'], ENT_QUOTES, 'UTF-8') . "</p>";
    }

} catch (Exception $e) {
    error_log("Application error: " . $e->getMessage());
    echo "Une erreur système est survenue.";
}
?>
```

### Solution alternative avec liste blanche

```php
<?php
// ✅ SOLUTION ALTERNATIVE - Liste blanche d'IDs

// Si vous avez un nombre fixe d'images
$validImageIds = [1, 2, 3, 4, 5]; // IDs d'images existantes

// Validation stricte
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);

if ($id === false || $id === null || !in_array($id, $validImageIds, true)) {
    die("ID d'image invalide");
}

// Requête préparée
$stmt = $pdo->prepare("
    SELECT id, title, url
    FROM list_images
    WHERE id = :id
    LIMIT 1
");

$stmt->execute(['id' => $id]);
$image = $stmt->fetch();

if ($image) {
    echo "<pre>";
    echo "ID: " . htmlspecialchars($image['id'], ENT_QUOTES, 'UTF-8') . " <br>";
    echo "Title: " . htmlspecialchars($image['title'], ENT_QUOTES, 'UTF-8') . "<br>";
    echo "Url : " . htmlspecialchars($image['url'], ENT_QUOTES, 'UTF-8');
    echo "</pre>";
} else {
    echo "Image non trouvée";
}
?>
```

---

## 🛡️ Mesures de sécurité additionnelles

### 1. Restrictions de la base de données

```sql
-- Créer un utilisateur dédié pour l'application images
CREATE USER 'images_app'@'localhost' IDENTIFIED BY 'strong_random_password';

-- Donner uniquement SELECT sur la table list_images
GRANT SELECT ON Member_images.list_images TO 'images_app'@'localhost';

-- Bloquer explicitement l'accès à information_schema
REVOKE ALL PRIVILEGES ON information_schema.* FROM 'images_app'@'localhost';

-- Bloquer l'accès aux autres bases
REVOKE ALL PRIVILEGES ON Member_Sql_Injection.* FROM 'images_app'@'localhost';
REVOKE ALL PRIVILEGES ON Member_guestbook.* FROM 'images_app'@'localhost';

FLUSH PRIVILEGES;

-- Vérifier les permissions
SHOW GRANTS FOR 'images_app'@'localhost';
```

### 2. Vue de base de données pour limiter les colonnes

```sql
-- Créer une vue qui expose uniquement les colonnes nécessaires
CREATE VIEW vw_public_images AS
SELECT
    id,
    title,
    url
FROM list_images
WHERE id > 0;  -- Exclure les IDs négatifs

-- Donner accès uniquement à la vue
GRANT SELECT ON Member_images.vw_public_images TO 'images_app'@'localhost';
REVOKE SELECT ON Member_images.list_images FROM 'images_app'@'localhost';
```

### 3. Validation avancée avec filtres PHP

```php
<?php
/**
 * Classe de validation pour les recherches d'images
 */
class ImageValidator {

    /**
     * Valide l'ID avec plusieurs règles
     */
    public static function validateId($input) {
        // Règle 1: Doit être un entier
        if (!filter_var($input, FILTER_VALIDATE_INT)) {
            throw new InvalidArgumentException("L'ID doit être un nombre entier");
        }

        $id = (int)$input;

        // Règle 2: Doit être positif
        if ($id <= 0) {
            throw new InvalidArgumentException("L'ID doit être positif");
        }

        // Règle 3: Limites raisonnables
        if ($id > 10000) {
            throw new InvalidArgumentException("ID hors limites");
        }

        // Règle 4: Vérifier qu'il ne contient pas de caractères SQL
        if (preg_match('/[^\d]/', $input)) {
            throw new InvalidArgumentException("L'ID contient des caractères invalides");
        }

        return $id;
    }

    /**
     * Sanitize la sortie
     */
    public static function sanitizeOutput($value, $type = 'text') {
        switch ($type) {
            case 'int':
                return (int)$value;
            case 'url':
                return filter_var($value, FILTER_SANITIZE_URL);
            case 'text':
            default:
                return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        }
    }
}

// Utilisation
try {
    $id = ImageValidator::validateId($_GET['id'] ?? null);

    $stmt = $pdo->prepare("SELECT id, title, url FROM list_images WHERE id = ? LIMIT 1");
    $stmt->execute([$id]);
    $image = $stmt->fetch();

    if ($image) {
        echo "ID: " . ImageValidator::sanitizeOutput($image['id'], 'int') . "<br>";
        echo "Title: " . ImageValidator::sanitizeOutput($image['title']) . "<br>";
        echo "Url: " . ImageValidator::sanitizeOutput($image['url'], 'url');
    }

} catch (InvalidArgumentException $e) {
    http_response_code(400);
    echo "Erreur: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
}
?>
```

---

## 🔒 Bonnes pratiques spécifiques

### ✅ Protection contre UNION SELECT:

1. **Requêtes préparées obligatoires**
   ```php
   // ✅ BON
   $stmt = $pdo->prepare("SELECT * FROM table WHERE id = ?");
   $stmt->execute([$id]);

   // ❌ MAUVAIS
   $query = "SELECT * FROM table WHERE id = " . $id;
   ```

2. **Validation stricte du type**
   ```php
   // ✅ BON - Force le type entier
   $id = filter_var($_GET['id'], FILTER_VALIDATE_INT);
   if ($id === false) die("Invalid ID");

   // ❌ MAUVAIS - Accepte n'importe quoi
   $id = $_GET['id'];
   ```

3. **Limiter les résultats**
   ```sql
   -- ✅ BON - Limite à 1 résultat
   SELECT * FROM images WHERE id = ? LIMIT 1

   -- ❌ MAUVAIS - Pas de limite
   SELECT * FROM images WHERE id = ?
   ```

4. **Masquer les noms de colonnes**
   ```php
   // ✅ BON - Utiliser des alias
   $stmt = $pdo->prepare("
       SELECT
           id AS image_id,
           title AS image_title,
           url AS image_url
       FROM list_images
       WHERE id = ?
   ");
   ```

---

## 🧪 Tests de validation

### Test 1: UNION SELECT basique
```
Input: 1 UNION SELECT 1,2
Résultat attendu: "ID invalide" ou traité comme ID = 1
```

### Test 2: UNION avec information_schema
```
Input: 1 UNION SELECT table_name,table_schema FROM information_schema.tables
Résultat attendu: Erreur de validation
```

### Test 3: Commentaire SQL
```
Input: 1-- comment
Résultat attendu: Erreur "caractères invalides"
```

### Test 4: Injection avec NULL
```
Input: 1 UNION SELECT NULL,NULL
Résultat attendu: Erreur de validation
```

### Test 5: ID valide
```
Input: 1
Résultat attendu: Affichage de l'image #1
```

### Test 6: Chaîne au lieu d'entier
```
Input: abc
Résultat attendu: "ID doit être un nombre entier"
```

---

## 📊 Comparaison avant/après

| Aspect | Avant (Vulnérable) | Après (Sécurisé) |
|--------|-------------------|------------------|
| Type de requête | Concaténation | Requête préparée |
| Validation | Aucune | Stricte (int, range) |
| UNION SELECT | ✅ Possible | ❌ Bloqué |
| Accès information_schema | ✅ Possible | ❌ Bloqué |
| Messages d'erreur | SQL affiché | Générique |
| Privilèges DB | Trop élevés | Minimum requis |
| Limite résultats | Aucune | LIMIT 1 |

---

## 🔍 Audit et monitoring

### 1. Détecter les tentatives d'injection

```php
<?php
/**
 * Logger les tentatives d'injection suspectes
 */
function logSuspiciousActivity($input, $ip) {
    // Mots-clés suspects
    $suspicious = ['union', 'select', 'information_schema', '--', '/*', 'drop', 'insert'];

    $inputLower = strtolower($input);

    foreach ($suspicious as $keyword) {
        if (strpos($inputLower, $keyword) !== false) {
            $logEntry = sprintf(
                "[%s] SQL Injection attempt from %s: %s\n",
                date('Y-m-d H:i:s'),
                $ip,
                $input
            );

            error_log($logEntry, 3, '/var/log/security/sql_injection_attempts.log');

            // Optionnel: bloquer l'IP après X tentatives
            // incrementFailedAttempts($ip);

            return true;
        }
    }
    return false;
}

// Utilisation
$input = $_GET['id'] ?? '';
if (logSuspiciousActivity($input, $_SERVER['REMOTE_ADDR'])) {
    http_response_code(403);
    die("Activité suspecte détectée");
}
?>
```

### 2. Monitoring des requêtes lentes

```sql
-- Activer le slow query log pour détecter les UNION
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 0.5;
SET GLOBAL log_queries_not_using_indexes = 'ON';
```

---

## 📚 Ressources et outils

### Documentation:
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [PHP PDO::prepare](https://www.php.net/manual/fr/pdo.prepare.php)

### Outils de test:
- **SQLMap**: Test automatisé de SQL injection
  ```bash
  sqlmap -u "http://192.168.10.146/?page=searchimg&id=1" --batch
  ```
- **jSQL Injection**: Interface graphique pour tests SQL
- **Burp Suite**: Interception et modification de requêtes

---

## ✅ Checklist de remédiation

- [ ] Remplacer toutes les concaténations par des requêtes préparées
- [ ] Valider et typer le paramètre `id` (entier strict)
- [ ] Créer un utilisateur DB avec privilèges minimaux
- [ ] Révoquer l'accès à information_schema
- [ ] Ajouter LIMIT 1 à la requête
- [ ] Implémenter le logging des tentatives suspectes
- [ ] Tester avec SQLMap
- [ ] Échapper toutes les sorties HTML
- [ ] Documenter la configuration sécurisée
- [ ] Former l'équipe sur les requêtes préparées

---

**Dernière mise à jour**: 2025-12-19
**Statut**: ✅ Remédiation complète

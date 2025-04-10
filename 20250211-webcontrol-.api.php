<?php
const DB_SEVER    = "localhost";
const DB_USERNAME = "owner01";
const DB_PASSWORD = "123456";
const DB_NAME     = "workdb";
const UPLOAD_DIR  = __DIR__ . '/upload/';  // 檔案上傳目錄
const THUMB_WIDTH = 3000;                  // 縮圖寬度

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");
header("Content-Type: application/json"); // 確保返回 JSON 格式

// 建立連線 (與原有邏輯保持不變)
function create_connection()
{
    $conn = mysqli_connect(DB_SEVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    if (!$conn) {
        echo json_encode(["state" => false, "message" => "連線失敗!"]);
        exit;
    }
    return $conn;
}

// 取得JSON資料 (與原有邏輯保持不變)
function get_json_input()
{
    $data = file_get_contents("php://input");
    return json_decode($data, true);
}

// 回復JSON訊息 (與原有邏輯保持不變)
function respond($state, $message, $data = null)
{
    echo json_encode(["state" => $state, "message" => $message, "data" => $data]);
    exit; // 確保不會有後續輸出
}

// 圖片處理函式
function process_image($file)
{
    if (!isset($file['name']) || $file['name'] === "") {
        return [false, '檔案不存在'];
    }
    // 檢查 MIME 類型（但並不完全可靠）
    $allowed_types = ['image/jpeg', 'image/png'];
    if (!in_array($file['type'], $allowed_types)) {
        return [false, '只允許 JPG/PNG 格式'];
    }
    if (!file_exists(UPLOAD_DIR)) {
        if (!mkdir(UPLOAD_DIR, 0777, true)) {
            error_log('Failed to create upload directory: ' . UPLOAD_DIR);
            return [false, '無法創建上傳目錄'];
        }
    }
    $filename = date("YmdHis") . "_" . basename($file['name']);
    $main_path = UPLOAD_DIR . $filename;
    $thumb_path = UPLOAD_DIR . 'thumb_' . $filename;
    // if (!move_uploaded_file($file['tmp_name'], $main_path)) {
    //     error_log('Failed to move uploaded file from ' . $file['tmp_name'] . ' to ' . $main_path);
    //     return [false, '檔案上傳失敗'];
    // }

    // 檢查是否為上傳檔案，若是則使用 move_uploaded_file，否則使用 rename
    if (is_uploaded_file($file['tmp_name'])) {
        if (!move_uploaded_file($file['tmp_name'], $main_path)) {
            error_log('Failed to move uploaded file from ' . $file['tmp_name'] . ' to ' . $main_path);
            return [false, '檔案上傳失敗'];
        }
    } else {
        if (!rename($file['tmp_name'], $main_path)) {
            error_log('Failed to rename file from ' . $file['tmp_name'] . ' to ' . $main_path);
            return [false, '檔案上傳失敗'];
        }
    }

    // 讀取檔案前幾個位元組判斷格式
    $fp = fopen($main_path, 'rb');
    $header = fread($fp, 8);
    fclose($fp);
    // PNG 的魔術字元為 89 50 4E 47 0D 0A 1A 0A
    $is_png = (substr($header, 0, 4) === "\x89PNG");

    try {
        if ($is_png) {
            $source = imagecreatefrompng($main_path);
        } else {
            $source = imagecreatefromjpeg($main_path);
        }
        $width = imagesx($source);
        $height = imagesy($source);
        $new_height = (int)(THUMB_WIDTH * ($height / $width));
        $thumb = imagecreatetruecolor(THUMB_WIDTH, $new_height);
        imagecopyresampled($thumb, $source, 0, 0, 0, 0, THUMB_WIDTH, $new_height, $width, $height);
        if ($is_png) {
            imagepng($thumb, $thumb_path, 0);
        } else {
            imagejpeg($thumb, $thumb_path, 90);
        }
        imagedestroy($source);
        imagedestroy($thumb);
    } catch (Exception $e) {
        unlink($main_path);
        error_log('Error processing image: ' . $e->getMessage());
        return [false, '圖片處理失敗'];
    }
    return [true, [
        "state"     => true,
        "message"   => "新增成功",
        "name"      => $file['name'],
        "location"  => $main_path,
        "type"      => $file['type'],
        "size"      => $file['size'],
        "image"     => $filename,
        "thumbnail" => 'thumb_' . $filename
    ]];
}




// 會員註冊 (新增 role 欄位)
function register_user()
{
    $input = get_json_input();
    $required = ["username", "password", "email", "address", "role"];

    // 檢查是否所有必填欄位都有傳入
    if (count(array_intersect_key(array_flip($required), $input)) === count($required)) {
        $p_username = trim($input["username"]);
        $p_password = password_hash(trim($input["password"]), PASSWORD_DEFAULT);
        $p_email    = trim($input["email"]);
        $p_address  = trim($input["address"]);
        $role       = in_array($input['role'], ['buyer', 'seller']) ? $input['role'] : 'buyer';

        if ($p_username && $p_password && $p_email && $p_address) {
            $conn = create_connection();
            $stmt = $conn->prepare("INSERT INTO member(Username, Password, Email, Address, role) VALUES(?, ?, ?, ?, ?)");
            $stmt->bind_param("sssss", $p_username, $p_password, $p_email, $p_address, $role);
            if ($stmt->execute()) {
                respond(true, "註冊成功");
            } else {
                respond(false, "註冊失敗");
            }
            $stmt->close();
            $conn->close();
        } else {
            respond(false, "欄位不得為空");
        }
    } else {
        respond(false, "欄位錯誤");
    }
}

// 會員登入 (與原有邏輯相同)
function login_user()
{
    $input = get_json_input();
    if (isset($input["username"], $input["password"])) {
        $p_username = trim($input["username"]);
        $p_password = trim($input["password"]);
        if ($p_username && $p_password) {
            $conn = create_connection();

            $stmt = $conn->prepare("SELECT * FROM member WHERE Username = ?");
            $stmt->bind_param("s", $p_username);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows === 1) {
                $row = $result->fetch_assoc();
                if (password_verify($p_password, $row["Password"])) {
                    // 產生 UID 並更新至資料庫
                    $uid01 = substr(hash("sha256", time()), 10, 5) . substr(bin2hex(random_bytes(16)), 1, 3);
                    $update_stmt = $conn->prepare("UPDATE member SET Uid01 = ? WHERE Username = ?");
                    $update_stmt->bind_param('ss', $uid01, $p_username);
                    if ($update_stmt->execute()) {
                        $user_stmt = $conn->prepare("SELECT Username, Email, Uid01, Create_at, role FROM member WHERE Username = ?");
                        $user_stmt->bind_param("s", $p_username);
                        $user_stmt->execute();
                        $user_data = $user_stmt->get_result()->fetch_assoc();
                        respond(true, "登入成功", $user_data);
                    } else {
                        respond(false, "登入失敗, UID 更新失敗!");
                    }
                } else {
                    respond(false, "登入失敗, 密碼錯誤!");
                }
            } else {
                respond(false, "登入失敗, 該帳號不存在!");
            }
            $stmt->close();
            $conn->close();
        } else {
            respond(false, "欄位不得為空!");
        }
    } else {
        respond(false, "欄位錯誤!");
    }
}

// 驗證重複 username
function checkuni_user()
{
    $input = get_json_input();
    if (isset($input["username"])) {
        $p_username = trim($input["username"]);
        if ($p_username) {
            $conn = create_connection();
            $stmt = $conn->prepare("SELECT Username FROM member WHERE Username = ?");
            $stmt->bind_param("s", $p_username);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result->num_rows === 1) {
                respond(false, "帳號已存在, 不可以使用");
            } else {
                respond(true, "帳號不存在, 可以使用");
            }
            $stmt->close();
            $conn->close();
        } else {
            respond(false, "欄位不得為空");
        }
    } else {
        respond(false, "欄位錯誤");
    }
}

// Uid 驗證
function checkuid_user()
{
    $input = get_json_input();
    if (isset($input["uid01"])) {
        $p_uid = trim($input["uid01"]);
        if ($p_uid) {
            $conn = create_connection();
            $stmt = $conn->prepare("SELECT * FROM member WHERE Uid01 = ?");
            $stmt->bind_param("s", $p_uid);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result->num_rows === 1) {
                $userdata = $result->fetch_assoc();
                respond(true, "驗證成功", $userdata);
            } else {
                respond(false, "驗證失敗!");
            }
            $stmt->close();
            $conn->close();
        } else {
            respond(false, "欄位不得為空");
        }
    } else {
        respond(false, "欄位錯誤");
    }
}


// 取得所有會員資料
function get_all_user_data()
{
    $conn = create_connection();
    $stmt = $conn->prepare("SELECT * FROM member ORDER BY User_id DESC");
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        $mydata = array();
        while ($row = $result->fetch_assoc()) {
            unset($row["Password"]);
            unset($row["Uid01"]);
            $mydata[] = $row;
        }
        respond(true, "取得所有會員資料成功", $mydata);
    } else {
        respond(false, "查無資料");
    }


    $stmt->close();
    $conn->close();
}

function get_my_data()
{
    // 從 GET 參數中取得 uid01
    $uid = $_GET['uid01'] ?? '';
    if (!$uid) {
        respond(false, "必要欄位不得為空");
    }

    $conn = create_connection();
    // 只查詢符合該 uid 的會員資料
    $stmt = $conn->prepare("SELECT * FROM member WHERE Uid01 = ?");
    $stmt->bind_param("s", $uid);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 1) {
        $row = $result->fetch_assoc();
        // 重新計算會員等級：每完成 5 筆訂單升一級，最低 1 級，最高 5 級
        $row["discount_level"] = min(5, floor($row["order_count"] / 5) + 1);
        // 移除不必要的敏感資料
        unset($row["Password"]);
        unset($row["Uid01"]);
        respond(true, "取得會員資料成功", $row);
    } else {
        respond(false, "查無資料");
    }
    $stmt->close();
    $conn->close();
}



// 會員更新
function update_user()
{
    $input = get_json_input();
    if (isset($input["id"], $input["email"], $input["address"])) {
        $p_id       = trim($input["id"]);
        $p_email    = trim($input["email"]);
        $p_address  = trim($input["address"]);
        if ($p_id && $p_email && $p_address) {
            $conn = create_connection();
            $stmt = $conn->prepare("UPDATE member SET Email = ? , Address = ? WHERE User_id = ?");
            $stmt->bind_param("ssi",  $p_email, $p_address, $p_id);
            if ($stmt->execute()) {
                if ($stmt->affected_rows === 1) {
                    respond(true, "會員更新成功");
                } else {
                    respond(false, "會員更新失敗，並無更新行為");
                }
            } else {
                respond(false, "會員更新失敗");
            }
            $stmt->close();
            $conn->close();
        } else {
            respond(false, "欄位不得為空");
        }
    } else {
        respond(false, "欄位錯誤");
    }
}

// 會員刪除
function delete_user()
{
    $input = get_json_input();
    if (isset($input["id"])) {
        $p_id = trim($input["id"]);
        if ($p_id) {
            $conn = create_connection();
            $stmt = $conn->prepare("DELETE FROM member WHERE User_id = ?");
            $stmt->bind_param("i", $p_id);
            if ($stmt->execute()) {
                if ($stmt->affected_rows === 1) {
                    respond(true, "會員刪除成功");
                } else {
                    respond(false, "會員刪除失敗，並無刪除行為");
                }
            } else {
                respond(false, "會員刪除失敗");
            }
            $stmt->close();
            $conn->close();
        } else {
            respond(false, "欄位不得為空");
        }
    } else {
        respond(false, "欄位錯誤");
    }
}

function checkuni_product()
{
    $input = get_json_input();
    if (isset($input["name"])) {
        $name = trim($input["name"]);
        if (!$name) {
            respond(false, "產品名稱不得為空");
        }
        $conn = create_connection();
        // 檢查產品名稱是否已存在
        $stmt = $conn->prepare("SELECT menu_id FROM menus WHERE name = ?");
        $stmt->bind_param("s", $name);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            respond(false, "產品名稱已存在，請使用其他名稱");
        } else {
            respond(true, "產品名稱可用");
        }
        $stmt->close();
        $conn->close();
    } else {
        respond(false, "欄位錯誤");
    }
}


// 產品上傳 (新增賣家權限檢查與圖片處理)
function upload_product()
{
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        error_log("Received POST request");
        // 驗證賣家身份，參數名稱統一使用 uid01 (修改處)
        $uid = $_POST['uid01'] ?? '';
        error_log("Received UID: $uid"); // 用於除錯

        $conn = create_connection();
        $stmt = $conn->prepare("SELECT User_id, role FROM member WHERE Uid01 = ?");
        $stmt->bind_param("s", $uid);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();

        error_log("User Role: " . ($user['role'] ?? 'None')); // 用於除錯

        if (!$user || $user['role'] !== 'seller') {
            respond(false, "無操作權限");
        }

        // 檢查必填欄位（新增 category）
        if (!isset($_POST['name']) || !isset($_POST['price']) || !isset($_POST['category'])) {
            respond(false, "商品名稱、價格和分類為必填");
        }

        $name = trim($_POST['name']);
        $price = floatval($_POST['price']);
        $category = trim($_POST['category']);
        $description = isset($_POST['description']) ? trim($_POST['description']) : "";

        // 如果沒有上傳檔案，但有 captured_image，則從該 URL 下載圖片
        if (empty($_FILES['image']['name']) && isset($_POST['captured_image']) && !empty($_POST['captured_image'])) {
            $url = $_POST['captured_image'];
            $contents = file_get_contents($url);
            if ($contents === false) {
                respond(false, "下載圖片失敗");
            }
            $image_info = getimagesizefromstring($contents);
            if (!$image_info) {
                respond(false, "圖片資訊錯誤");
            }
            $mime = $image_info['mime'];
            $allowed_types = ['image/jpeg', 'image/png'];
            if (!in_array($mime, $allowed_types)) {
                respond(false, "只允許 JPG/PNG 格式");
            }
            $ext = ($mime == 'image/png') ? '.png' : '.jpg';
            $filename = date("YmdHis") . "_" . uniqid() . $ext;
            $main_path = UPLOAD_DIR . $filename;
            if (file_put_contents($main_path, $contents) === false) {
                respond(false, "儲存圖片失敗");
            }
            // 模擬檔案上傳資料
            $_FILES['image'] = [
                'name' => basename($filename),
                'tmp_name' => $main_path,
                'type' => $mime,
                'size' => filesize($main_path)
            ];
        }

        // 處理圖片上傳
        if (empty($_FILES['image']) || empty($_FILES['image']['name'])) {
            respond(false, "請上傳商品圖片");
        }
        list($success, $image_data) = process_image($_FILES['image']);
        if (!$success) {
            respond(false, $image_data);
        }
        // 儲存商品資料至 menus 資料表
        $stmt = $conn->prepare("INSERT INTO menus (seller_id, name, price, description, category, image, thumbnail, status) 
        VALUES (?, ?, ?, ?, ?, ?, ?, '上架')");
        // 修改處：將 $image_data['main'] 改為 $image_data['image']，$image_data['thumb'] 改為 $image_data['thumbnail']
        $stmt->bind_param(
            "isdssss",
            $user['User_id'],
            $name,
            $price,
            $description,
            $category,
            $image_data['image'],
            $image_data['thumbnail']
        );

        if ($stmt->execute()) {
            respond(true, "商品上傳成功");
        } else {
            // 若失敗則刪除上傳的圖片
            unlink(UPLOAD_DIR . $image_data['image']);
            unlink(UPLOAD_DIR . $image_data['thumbnail']);
            respond(false, "商品建立失敗");
        }
    } else {
        error_log("Request method is not POST");
        respond(false, "Invalid request method");
    }
    $stmt->close();
    $conn->close();
}

function get_product_list()
{
    // 從 GET 參數中取得 uid01
    $uid = $_GET['uid01'] ?? '';
    if (!$uid) {
        respond(false, "必要欄位不得為空");
    }

    $conn = create_connection();

    // 先取得該 uid 對應的會員資料，以獲得 User_id
    $stmt = $conn->prepare("SELECT User_id FROM member WHERE Uid01 = ?");
    $stmt->bind_param("s", $uid);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows !== 1) {
        respond(false, "無效的賣家身份");
    }
    $user = $result->fetch_assoc();
    $seller_id = $user['User_id'];
    $stmt->close();

    // 根據 seller_id 查詢該賣家上傳的所有商品
    $stmt2 = $conn->prepare("SELECT * FROM menus WHERE seller_id = ? ORDER BY menu_id DESC");
    $stmt2->bind_param("i", $seller_id);
    $stmt2->execute();
    $result2 = $stmt2->get_result();

    $products = array();
    while ($row = $result2->fetch_assoc()) {
        $products[] = $row;
    }

    if (count($products) > 0) {
        respond(true, "取得產品列表成功", $products);
    } else {
        respond(false, "查無資料");
    }

    $stmt2->close();
    $conn->close();
}

function get_product()
{
    // 從 GET 參數中取得 product_id
    $product_id = $_GET['product_id'] ?? '';
    if (!$product_id) {
        respond(false, "必要欄位不得為空");
    }

    $conn = create_connection();
    $stmt = $conn->prepare("SELECT * FROM menus WHERE menu_id = ?");
    $stmt->bind_param("i", $product_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 1) {
        $product = $result->fetch_assoc();
        respond(true, "取得商品資料成功", $product);
    } else {
        respond(false, "無法取得商品資料");
    }
    $stmt->close();
    $conn->close();
}

// 新增：取得所有上架商品
function get_all_products()
{
    $conn = create_connection();
    $stmt = $conn->prepare("SELECT * FROM menus WHERE status = '上架' ORDER BY menu_id DESC");
    $stmt->execute();
    $result = $stmt->get_result();
    $products = array();
    while ($row = $result->fetch_assoc()) {
        $products[] = $row;
    }
    if (count($products) > 0) {
        respond(true, "取得所有上架商品成功", $products);
    } else {
        respond(false, "查無上架商品");
    }
    $stmt->close();
    $conn->close();
}


// 產品更新 (包含圖片更新)
function update_product()
{
    // 修改處：統一使用 uid01 作為參數名稱
    $uid = $_POST['uid01'] ?? '';
    $product_id = $_POST['product_id'] ?? '';
    $name = trim($_POST['name'] ?? '');
    $price = isset($_POST['price']) ? floatval($_POST['price']) : 0;
    $description = trim($_POST['description'] ?? '');
    $category = trim($_POST['category'] ?? '');

    if (!$uid || !$product_id || !$name || !$price || !$category) {
        respond(false, "必要欄位不得為空");
        return;
    }

    $conn = create_connection();
    // 驗證賣家身份與商品所有權
    $stmt = $conn->prepare("SELECT m.User_id, m.role FROM member m JOIN menus p ON m.User_id = p.seller_id WHERE m.Uid01 = ? AND p.menu_id = ?");
    $stmt->bind_param("si", $uid, $product_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    if (!$row || $row['role'] !== 'seller') {
        respond(false, "無操作權限或商品不存在");
        return;
    }

    // 若有上傳新圖片則處理並刪除舊圖片
    if (isset($_FILES['image']) && $_FILES['image']['error'] !== UPLOAD_ERR_NO_FILE && $_FILES['image']['name'] !== "") {
        list($success, $image_data) = process_image($_FILES['image']);
        if (!$success) {
            respond(false, $image_data);
            return;
        }
        $stmt_old = $conn->prepare("SELECT image, thumbnail FROM menus WHERE menu_id = ?");
        $stmt_old->bind_param("i", $product_id);
        $stmt_old->execute();
        $old_images = $stmt_old->get_result()->fetch_assoc();
        if ($old_images) {
            if (file_exists(UPLOAD_DIR . $old_images['image'])) unlink(UPLOAD_DIR . $old_images['image']);
            if (file_exists(UPLOAD_DIR . $old_images['thumbnail'])) unlink(UPLOAD_DIR . $old_images['thumbnail']);
        }
        $stmt_old->close();

        // 更新包含圖片的資料
        $sql = "UPDATE menus SET name = ?, price = ?, description = ?, category = ?, image = ?, thumbnail = ? WHERE menu_id = ?";
        $stmt_update = $conn->prepare($sql);
        // 修改處：將 $image_data['main'] 改為 $image_data['image']，$image_data['thumb'] 改為 $image_data['thumbnail']
        $stmt_update->bind_param("sdssssi", $name, $price, $description, $category, $image_data['image'], $image_data['thumbnail'], $product_id);
    } else {
        // 更新不含圖片的資料
        $sql = "UPDATE menus SET name = ?, price = ?, description = ?, category = ? WHERE menu_id = ?";
        $stmt_update = $conn->prepare($sql);
        $stmt_update->bind_param("sdssi", $name, $price, $description, $category, $product_id);
    }

    if ($stmt_update->execute()) {
        respond(true, "商品更新成功");
    } else {
        respond(false, "商品更新失敗");
    }
    $stmt_update->close();
    $conn->close();
}


// 產品刪除
function delete_product()
{
    // 修改處：統一使用 uid01 作為參數名稱
    $uid = $_GET['uid01'] ?? '';
    $product_id = $_GET['product_id'] ?? '';
    if (!$uid || !$product_id) {
        respond(false, "必要欄位不得為空");
        return;
    }
    $conn = create_connection();
    // 驗證賣家身份與商品所有權
    $stmt = $conn->prepare("SELECT m.User_id, m.role, p.image, p.thumbnail FROM member m JOIN menus p ON m.User_id = p.seller_id WHERE m.Uid01 = ? AND p.menu_id = ?");
    $stmt->bind_param("si", $uid, $product_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $product = $result->fetch_assoc();
    if (!$product || $product['role'] !== 'seller') {
        respond(false, "無操作權限或商品不存在");
        return;
    }
    // 刪除圖片
    if (file_exists(UPLOAD_DIR . $product['image'])) unlink(UPLOAD_DIR . $product['image']);
    if (file_exists(UPLOAD_DIR . $product['thumbnail'])) unlink(UPLOAD_DIR . $product['thumbnail']);

    $stmt = $conn->prepare("DELETE FROM menus WHERE menu_id = ?");
    $stmt->bind_param("i", $product_id);
    if ($stmt->execute() && $stmt->affected_rows === 1) {
        respond(true, "商品刪除成功");
    } else {
        respond(false, "商品刪除失敗");
    }
    $stmt->close();
    $conn->close();
}

// 新增：取得優惠折扣碼 (僅返回該會員所屬的優惠碼)
function get_discount_code()
{
    // 從 GET 參數中取得 uid01
    $uid = $_GET['uid01'] ?? '';
    if (!$uid) {
        respond(false, "必要欄位不得為空");
    }

    $conn = create_connection();
    // 取得會員的 order_count，而非 discount_level
    $stmt = $conn->prepare("SELECT order_count FROM member WHERE Uid01 = ?");
    $stmt->bind_param("s", $uid);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $row = $result->fetch_assoc();
        $order_count = $row['order_count'];
        // 根據 order_count 動態計算等級，每 5 筆訂單升一級，最低 1 最高 5
        $level = min(5, floor($order_count / 5) + 1);
        $code = generateDiscountCode($level);
        respond(true, "取得優惠碼成功", ["discount_level" => $level, "discount_code" => $code]);
    } else {
        respond(false, "會員不存在");
    }
    $stmt->close();
    $conn->close();
}


// 依照會員等級產生優惠折扣碼
function generateDiscountCode($level)
{
    // 根據等級產生對應的前綴，例如 LV1、LV2、……LV5
    $prefix = "LV" . $level . "-";
    // 隨機亂碼 (可自行調整長度)
    $random_str = substr(str_shuffle("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"), 0, 10);
    return $prefix . $random_str;
}


// 買家升級檢查 (在訂單完成時呼叫)
function check_level_up($user_id)
{
    $conn = create_connection();
    $stmt = $conn->prepare("SELECT order_count FROM member WHERE User_id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $count = $stmt->get_result()->fetch_assoc()['order_count'];
    $new_level = min(5, floor($count / 5) + 1); // 每 5 筆訂單升一級
    $stmt = $conn->prepare("UPDATE member SET discount_level = ? WHERE User_id = ?");
    $stmt->bind_param("ii", $new_level, $user_id);
    $stmt->execute();
    $stmt->close();
    $conn->close();
}

// --------------------------
// 購物車相關 API
// --------------------------

// 加入購物車：必須傳入 uid01 與 menu_id (POST)
function add_to_cart()
{
    $input = get_json_input();
    if (!isset($input['uid01']) || !isset($input['menu_id'])) {
        respond(false, "必要欄位不得為空");
    }
    $uid = trim($input['uid01']);
    $menu_id = intval($input['menu_id']);
    if (!$uid || !$menu_id) {
        respond(false, "欄位不得為空");
    }
    $conn = create_connection();
    // 驗證會員身份
    $stmt = $conn->prepare("SELECT User_id, role FROM member WHERE Uid01 = ?");
    $stmt->bind_param("s", $uid);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows !== 1) {
        respond(false, "無效的使用者");
    }
    $user = $result->fetch_assoc();
    if ($user['role'] !== 'buyer') {
        respond(false, "只有買家可以加入購物車");
    }
    $buyer_id = $user['User_id'];
    $stmt->close();

    // 檢查商品是否存在且上架
    $stmt = $conn->prepare("SELECT menu_id, price FROM menus WHERE menu_id = ? AND status = '上架'");
    $stmt->bind_param("i", $menu_id);
    $stmt->execute();
    $prod_result = $stmt->get_result();
    if ($prod_result->num_rows !== 1) {
        respond(false, "商品不存在或未上架");
    }
    $stmt->close();

    // 將商品加入購物車 (buyer_id 與 menu_id 組合設定 UNIQUE 防止重複)
    $stmt = $conn->prepare("INSERT INTO shopping_cart (buyer_id, menu_id) VALUES (?, ?)");
    $stmt->bind_param("ii", $buyer_id, $menu_id);
    if ($stmt->execute()) {
        respond(true, "已加入購物車");
    } else {
        respond(false, "加入購物車失敗");
    }
    $stmt->close();
    $conn->close();
}

// 從購物車移除商品：需傳入 uid01 與 menu_id (DELETE)
function remove_from_cart()
{
    $input = get_json_input();
    if (!isset($input['uid01']) || !isset($input['menu_id'])) {
        respond(false, "必要欄位不得為空");
    }
    $uid = trim($input['uid01']);
    $menu_id = intval($input['menu_id']);
    if (!$uid || !$menu_id) {
        respond(false, "欄位不得為空");
    }
    $conn = create_connection();
    // 驗證會員身份
    $stmt = $conn->prepare("SELECT User_id, role FROM member WHERE Uid01 = ?");
    $stmt->bind_param("s", $uid);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows !== 1) {
        respond(false, "無效的使用者");
    }
    $user = $result->fetch_assoc();
    if ($user['role'] !== 'buyer') {
        respond(false, "只有買家可以操作購物車");
    }
    $buyer_id = $user['User_id'];
    $stmt->close();

    // 從購物車中刪除該商品
    $stmt = $conn->prepare("DELETE FROM shopping_cart WHERE buyer_id = ? AND menu_id = ?");
    $stmt->bind_param("ii", $buyer_id, $menu_id);
    if ($stmt->execute() && $stmt->affected_rows > 0) {
        respond(true, "已從購物車移除");
    } else {
        respond(false, "移除購物車失敗");
    }
    $stmt->close();
    $conn->close();
}

// 取得購物車資料：需傳入 uid01 (GET)
function get_cart_items()
{
    $uid = $_GET['uid01'] ?? '';
    if (!$uid) {
        respond(false, "必要欄位不得為空");
    }
    $uid = trim($uid);
    $conn = create_connection();
    // 取得買家資料
    $stmt = $conn->prepare("SELECT User_id, role FROM member WHERE Uid01 = ?");
    $stmt->bind_param("s", $uid);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows !== 1) {
        respond(false, "無效的使用者");
    }
    $user = $result->fetch_assoc();
    if ($user['role'] !== 'buyer') {
        respond(false, "只有買家可以操作購物車");
    }
    $buyer_id = $user['User_id'];
    $stmt->close();

    // 取得購物車內的商品，並加入商品資訊
    $stmt = $conn->prepare("SELECT sc.cart_item_id, sc.menu_id, m.name, m.price, m.description, m.category, m.image, m.thumbnail
                            FROM shopping_cart sc
                            JOIN menus m ON sc.menu_id = m.menu_id
                            WHERE sc.buyer_id = ?");
    $stmt->bind_param("i", $buyer_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $items = [];
    while ($row = $result->fetch_assoc()) {
        $items[] = $row;
    }
    respond(true, "取得購物車資料成功", $items);
    $stmt->close();
    $conn->close();
}


// --------------------------
// 訂單相關 API
// --------------------------

// 建立訂單 (結帳)：僅針對購物車內所有商品建立一筆訂單 (POST)
function create_order() {
    $input = get_json_input();
    // 檢查必填欄位
    if (
        !isset($input['uid01']) || 
        !isset($input['payment_method']) || 
        !isset($input['shipping_method']) || 
        !isset($input['shipping_address'])
    ) {
        respond(false, "必要欄位不得為空");
    }
    $uid = trim($input['uid01']);
    $payment_method = trim($input['payment_method']);
    $shipping_method = trim($input['shipping_method']);
    $shipping_address = trim($input['shipping_address']);
    if (!$uid || !$payment_method || !$shipping_method || !$shipping_address) {
        respond(false, "欄位不得為空");
    }
    // 取得前端傳入的運費，如果沒有則預設為 60.00
    $shipping_fee = isset($input['shipping_fee']) ? floatval($input['shipping_fee']) : 60.00;

    $conn = create_connection();
    // 驗證買家身份
    $stmt = $conn->prepare("SELECT User_id, role FROM member WHERE Uid01 = ?");
    $stmt->bind_param("s", $uid);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows !== 1) {
        respond(false, "無效的使用者");
    }
    $user = $result->fetch_assoc();
    if ($user['role'] !== 'buyer') {
        respond(false, "只有買家可以下訂單");
    }
    $buyer_id = $user['User_id'];
    $stmt->close();

    // 取得該買家購物車內所有商品
$stmt = $conn->prepare("SELECT sc.menu_id, m.price, m.name, m.category 
FROM shopping_cart sc
JOIN menus m ON sc.menu_id = m.menu_id
WHERE sc.buyer_id = ?");
$stmt->bind_param("i", $buyer_id);
$stmt->execute();
$result = $stmt->get_result();
$cart_items = [];
while ($row = $result->fetch_assoc()) {
$cart_items[] = $row;
}
$stmt->close();

if (empty($cart_items)) {
respond(false, "購物車沒有商品");
}

// 計算產品總金額
$product_total = 0;
foreach ($cart_items as $item) {
$product_total += $item['price'];
}
$total_amount = $product_total + $shipping_fee;

// 【新增】建立訂單並取得 order_id
$stmt = $conn->prepare("INSERT INTO orders (buyer_id, total_amount, payment_method, shipping_method, shipping_address, shipping_fee, order_status)
VALUES (?, ?, ?, ?, ?, ?, '待付款')");
$stmt->bind_param("idsssd", $buyer_id, $total_amount, $payment_method, $shipping_method, $shipping_address, $shipping_fee);
if (!$stmt->execute()) {
respond(false, "建立訂單失敗");
}
$order_id = $stmt->insert_id; // 取得新訂單ID
$stmt->close();

// 建立訂單明細 (記錄當時價格、商品名稱與種類)
$stmt = $conn->prepare("INSERT INTO order_items (order_id, menu_id, price, product_name, product_category)
VALUES (?, ?, ?, ?, ?)");
foreach ($cart_items as $item) {
$menu_id = $item['menu_id'];
$price = $item['price'];
$product_name = $item['name'];
$product_category = $item['category'];
$stmt->bind_param("iidss", $order_id, $menu_id, $price, $product_name, $product_category);
if (!$stmt->execute()) {
respond(false, "建立訂單明細失敗");
}
}
$stmt->close();

// 更新購物車中每個商品的狀態（若你希望在結帳後改變商品狀態）
foreach ($cart_items as $item) {
$menu_id = $item['menu_id'];
$stmt = $conn->prepare("UPDATE menus SET status = '下架' WHERE menu_id = ?");
$stmt->bind_param("i", $menu_id);
if (!$stmt->execute()) {
respond(false, "更新商品狀態失敗");
}
$stmt->close();
}

// 清空該買家的購物車
$stmt = $conn->prepare("DELETE FROM shopping_cart WHERE buyer_id = ?");
$stmt->bind_param("i", $buyer_id);
$stmt->execute();
$stmt->close();

// 更新會員訂單數量：結帳成功後訂單數量加 1
$stmt = $conn->prepare("UPDATE member SET order_count = order_count + 1 WHERE User_id = ?");
$stmt->bind_param("i", $buyer_id);
$stmt->execute();
$stmt->close();

respond(true, "訂單建立成功", ["order_id" => $order_id, "total_amount" => $total_amount]);
$conn->close();

}



// 取得訂單列表：需傳入 uid01 (GET)
function get_order_list()
{
    $uid = $_GET['uid01'] ?? '';
    if (!$uid) {
        respond(false, "必要欄位不得為空");
    }
    $uid = trim($uid);
    $conn = create_connection();
    // 取得買家資料
    $stmt = $conn->prepare("SELECT User_id, role FROM member WHERE Uid01 = ?");
    $stmt->bind_param("s", $uid);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows !== 1) {
        respond(false, "無效的使用者");
    }
    $user = $result->fetch_assoc();
    if ($user['role'] !== 'buyer') {
        respond(false, "只有買家可以查看訂單");
    }
    $buyer_id = $user['User_id'];
    $stmt->close();

    // 取得該買家所有訂單，並JOIN order_items 取得商品名稱與類別（假設一筆訂單只有一項商品）
    $query = "SELECT o.order_id, o.order_date, o.total_amount, oi.product_name, oi.product_category 
              FROM orders o 
              JOIN order_items oi ON o.order_id = oi.order_id 
              WHERE o.buyer_id = ? 
              ORDER BY o.order_date DESC";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $buyer_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $orders = [];
    while ($row = $result->fetch_assoc()) {
        $orders[] = $row;
    }
    respond(true, "取得訂單列表成功", $orders);
    $stmt->close();
    $conn->close();
}

// 取得訂單詳情：需傳入 uid01 與 order_id (GET)
function get_order_details() {
    $uid = $_GET['uid01'] ?? '';
    $order_id = $_GET['order_id'] ?? '';
    if (!$uid || !$order_id) {
        respond(false, "必要欄位不得為空");
    }
    $uid = trim($uid);
    $order_id = intval($order_id);
    $conn = create_connection();
    // 取得買家資料
    $stmt = $conn->prepare("SELECT User_id, role FROM member WHERE Uid01 = ?");
    $stmt->bind_param("s", $uid);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows !== 1) {
        respond(false, "無效的使用者");
    }
    $user = $result->fetch_assoc();
    if ($user['role'] !== 'buyer') {
        respond(false, "只有買家可以查看訂單");
    }
    $buyer_id = $user['User_id'];
    $stmt->close();

    // 檢查訂單是否屬於該買家
    $stmt = $conn->prepare("SELECT order_id, order_date, total_amount, payment_method, shipping_method, shipping_address, shipping_fee, order_status FROM orders WHERE order_id = ? AND buyer_id = ?");
    $stmt->bind_param("ii", $order_id, $buyer_id);
    $stmt->execute();
    $order_result = $stmt->get_result();
    if ($order_result->num_rows !== 1) {
        respond(false, "訂單不存在");
    }
    $order = $order_result->fetch_assoc();
    $stmt->close();

    // 取得該訂單的明細，並加入商品資訊
    $stmt = $conn->prepare("SELECT oi.order_item_id, oi.menu_id, oi.price, m.name, m.description, m.category, m.image, m.thumbnail
                            FROM order_items oi
                            JOIN menus m ON oi.menu_id = m.menu_id
                            WHERE oi.order_id = ?");
    $stmt->bind_param("i", $order_id);
    $stmt->execute();
    $items_result = $stmt->get_result();
    $order_items = [];
    while ($row = $items_result->fetch_assoc()) {
        $order_items[] = $row;
    }
    $stmt->close();
    $conn->close();

    $order['items'] = $order_items;
    respond(true, "取得訂單詳情成功", $order);
}


// (選用) 取消訂單：僅能取消狀態為 '待付款' 的訂單 (DELETE)
function delete_order()
{
    $input = get_json_input();
    if (!isset($input['uid01']) || !isset($input['order_id'])) {
        respond(false, "必要欄位不得為空");
    }
    $uid = trim($input['uid01']);
    $order_id = intval($input['order_id']);
    if (!$uid || !$order_id) {
        respond(false, "必要欄位不得為空");
    }
    $conn = create_connection();
    // 取得買家資料
    $stmt = $conn->prepare("SELECT User_id, role FROM member WHERE Uid01 = ?");
    $stmt->bind_param("s", $uid);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows !== 1) {
        respond(false, "無效的使用者");
    }
    $user = $result->fetch_assoc();
    if ($user['role'] !== 'buyer') {
        respond(false, "只有買家可以取消訂單");
    }
    $buyer_id = $user['User_id'];
    $stmt->close();

    // 檢查訂單狀態是否為 '待付款'
    $stmt = $conn->prepare("SELECT order_status FROM orders WHERE order_id = ? AND buyer_id = ?");
    $stmt->bind_param("ii", $order_id, $buyer_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows !== 1) {
        respond(false, "訂單不存在");
    }
    $order = $result->fetch_assoc();
    if ($order['order_status'] !== '待付款') {
        respond(false, "只有待付款訂單可以取消");
    }
    $stmt->close();

    // 刪除訂單明細
    $stmt = $conn->prepare("DELETE FROM order_items WHERE order_id = ?");
    $stmt->bind_param("i", $order_id);
    $stmt->execute();
    $stmt->close();

    // 刪除訂單
    $stmt = $conn->prepare("DELETE FROM orders WHERE order_id = ?");
    $stmt->bind_param("i", $order_id);
    if ($stmt->execute() && $stmt->affected_rows > 0) {
        respond(true, "訂單已取消");
    } else {
        respond(false, "取消訂單失敗");
    }
    $stmt->close();
    $conn->close();
}

function create_order_direct() {
    $input = get_json_input();
    if (
        !isset($input['uid01']) || 
        !isset($input['menu_id']) || 
        !isset($input['payment_method']) || 
        !isset($input['shipping_method']) || 
        !isset($input['shipping_address'])
    ) {
        respond(false, "必要欄位不得為空");
    }
    $uid = trim($input['uid01']);
    $menu_id = intval($input['menu_id']);
    $payment_method = trim($input['payment_method']);
    $shipping_method = trim($input['shipping_method']);
    $shipping_address = trim($input['shipping_address']);
    if (!$uid || !$menu_id || !$payment_method || !$shipping_method || !$shipping_address) {
        respond(false, "欄位不得為空");
    }
    // 取得前端傳入的運費，如果沒有則預設為 60.00
    $shipping_fee = isset($input['shipping_fee']) ? floatval($input['shipping_fee']) : 60.00;

    $conn = create_connection();
    // 驗證買家身份
    $stmt = $conn->prepare("SELECT User_id, role FROM member WHERE Uid01 = ?");
    $stmt->bind_param("s", $uid);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows !== 1) {
        respond(false, "無效的使用者");
    }
    $user = $result->fetch_assoc();
    if ($user['role'] !== 'buyer') {
        respond(false, "只有買家可以下訂單");
    }
    $buyer_id = $user['User_id'];
    $stmt->close();

    // 檢查商品是否存在且上架
    $stmt = $conn->prepare("SELECT menu_id, price FROM menus WHERE menu_id = ? AND status = '上架'");
    $stmt->bind_param("i", $menu_id);
    $stmt->execute();
    $prod_result = $stmt->get_result();
    if ($prod_result->num_rows !== 1) {
        respond(false, "商品不存在或未上架");
    }
    $product = $prod_result->fetch_assoc();
    $price = $product['price'];
    $stmt->close();

    // 計算總金額：單一商品價格 + 運費
    $total_amount = $price + $shipping_fee;

    // 建立訂單，並將運費存入 shipping_fee 欄位
    $stmt = $conn->prepare("INSERT INTO orders (buyer_id, total_amount, payment_method, shipping_method, shipping_address, shipping_fee, order_status) VALUES (?, ?, ?, ?, ?, ?, '待付款')");
    $stmt->bind_param("idsssd", $buyer_id, $total_amount, $payment_method, $shipping_method, $shipping_address, $shipping_fee);
    if (!$stmt->execute()) {
        respond(false, "建立訂單失敗");
    }
    $order_id = $stmt->insert_id;
    $stmt->close();

    // 建立訂單明細 (記錄當時價格、商品名稱與種類)
    $stmt = $conn->prepare("SELECT menu_id, price, name, category FROM menus WHERE menu_id = ? AND status = '上架'");
    $stmt->bind_param("i", $menu_id);
    $stmt->execute();
    $prod_result = $stmt->get_result();
    if ($prod_result->num_rows !== 1) {
        respond(false, "商品不存在或未上架");
    }
    $product = $prod_result->fetch_assoc();
    $price = $product['price'];
    $product_name = $product['name'];
    $product_category = $product['category'];
    $stmt->close();
    
    $stmt = $conn->prepare("INSERT INTO order_items (order_id, menu_id, price, product_name, product_category) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param("iidss", $order_id, $menu_id, $price, $product_name, $product_category);
    if (!$stmt->execute()) {
        respond(false, "建立訂單明細失敗");
    }
    $stmt->close();

    // 若該商品在購物車中存在，先將其移除
    $stmt = $conn->prepare("DELETE FROM shopping_cart WHERE buyer_id = ? AND menu_id = ?");
    $stmt->bind_param("ii", $buyer_id, $menu_id);
    $stmt->execute();
    $stmt->close();

    // 將商品狀態從「上架」改為「已售出」
    $stmt = $conn->prepare("UPDATE menus SET status = '下架' WHERE menu_id = ?");
    $stmt->bind_param("i", $menu_id);
    if (!$stmt->execute()) {
        respond(false, "無法更新商品狀態");
    }
    $stmt->close();

    //新增：更新會員訂單數量，完成結帳後訂單數量加 1
    $stmt = $conn->prepare("UPDATE member SET order_count = order_count + 1 WHERE User_id = ?");
    $stmt->bind_param("i", $buyer_id);
    $stmt->execute();
    $stmt->close();

    $conn->close();

    respond(true, "訂單建立成功", ["order_id" => $order_id, "total_amount" => $total_amount]);
}




// 獲取單一商品詳細資訊：需傳入 menu_id (GET)
function get_product_detail() {
    $menu_id = $_GET['menu_id'] ?? '';
    if (!$menu_id) {
        respond(false, "必要欄位不得為空");
    }

    $conn = create_connection();
    // 修改為只獲取上架商品
    $stmt = $conn->prepare("SELECT * FROM menus WHERE menu_id = ? AND status = '上架'");
    $stmt->bind_param("i", $menu_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 1) {
        $product = $result->fetch_assoc();
        respond(true, "取得商品資料成功", $product);
    } else {
        respond(false, "查無此商品或商品已售出");
    }
    
    $stmt->close();
    $conn->close();
}

function chart_data() {
    $uid = $_GET['uid01'] ?? '';
    if (!$uid) {
        respond(false, "必要欄位不得為空");
    }
    $conn = create_connection();
    // 取得使用者資料
    $stmt = $conn->prepare("SELECT User_id, role FROM member WHERE Uid01 = ?");
    $stmt->bind_param("s", $uid);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows !== 1) {
        respond(false, "無效的使用者");
    }
    $user = $result->fetch_assoc();
    $stmt->close();

    if ($user['role'] === 'seller') {
        // 取得該賣家近期銷售數據（依月份統計）
        $seller_id = $user['User_id'];
        $data = [];
        $query = "SELECT DATE_FORMAT(o.order_date, '%Y-%m') as month, COUNT(*) as sales
                  FROM orders o
                  JOIN order_items oi ON o.order_id = oi.order_id
                  JOIN menus m ON oi.menu_id = m.menu_id
                  WHERE m.seller_id = ?
                  GROUP BY month
                  ORDER BY month ASC";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("i", $seller_id);
        $stmt->execute();
        $result = $stmt->get_result();
        while ($row = $result->fetch_assoc()) {
            $data[] = $row;
        }
        $stmt->close();
        respond(true, "取得銷售數據成功", $data);
    } else if ($user['role'] === 'buyer') {
        // 取得該買家近期購買的書籍類型統計
        $buyer_id = $user['User_id'];
        $data = [];
        $query = "SELECT m.category, COUNT(*) as count
                  FROM orders o
                  JOIN order_items oi ON o.order_id = oi.order_id
                  JOIN menus m ON oi.menu_id = m.menu_id
                  WHERE o.buyer_id = ?
                  GROUP BY m.category";
        $stmt = $conn->prepare($query);
        $stmt->bind_param("i", $buyer_id);
        $stmt->execute();
        $result = $stmt->get_result();
        while ($row = $result->fetch_assoc()) {
            $data[] = $row;
        }
        $stmt->close();
        respond(true, "取得購買類型數據成功", $data);
    } else {
        respond(false, "未知角色");
    }
    $conn->close();
}


// 路由處理
$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';

if ($method === 'POST') {
    switch ($action) {
        case 'register':
            register_user();
            break;
        case 'login':
            login_user();
            break;
        case 'checkuni':
            checkuni_user();
            break;
        case 'checkuid':
            checkuid_user();
            break;
        case 'update':
            update_user();
            break;
        case 'product_create':
            upload_product();
            break;
        case 'product_update':
            update_product();
            break;
        case 'checkuni_product':
            checkuni_product();
            break;
        case 'cart_add':          //加入購物車
            add_to_cart();
            break;
        case 'order_create':      //建立訂單
            create_order();
            break;
        case 'order_create_direct':
            create_order_direct();
            break;
        default:
            respond(false, "無效操作");
    }
} else if ($method === 'GET') {
    switch ($action) {
        case 'getalldata':
            get_my_data();
            break;
        case 'product_detail':
            get_product_detail();  // 新增處理函數
            break;
        case 'product_list':
            get_product_list();
            break;
        case 'product_get':
            get_product();
            break;
        case 'allproducts':
            get_all_products();
            break;
        case 'discount':
            get_discount_code();
            break;
        case 'cart_get':          //取得購物車資料
            get_cart_items();
            break;
        case 'order_list':        //取得訂單列表
            get_order_list();
            break;
        case 'order_get':         //取得訂單詳情
            get_order_details();
            break;
        case 'chart_data':
            chart_data();
            break;
        default:
            respond(false, "無效操作");
    }
} else if ($method === 'DELETE') {
    switch ($action) {
        case 'delete':
            delete_user();
            break;
        case 'product_delete':
            delete_product();
            break;
        case 'cart_delete':       //從購物車移除商品
            remove_from_cart();
            break;
        case 'order_delete':      //取消訂單
            delete_order();
            break;
        default:
            respond(false, "無效操作");
    }
} else {
    respond(false, "無效的請求方法");
}

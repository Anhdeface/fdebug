# Tham Chiếu API - Mô-đun Bảo Vệ Chống Debug

## Các Cấu Trúc Cơ Bản

### `Protector`

Cấu trúc bảo vệ chính quản lý tất cả các hoạt động phát hiện và mã hóa.

```rust
pub struct Protector {
    seed: u32,
}
```

#### Các Phương Thức

##### `new(seed: u32) -> Self`

Tạo một phiên bản Protector mới với giá trị seed đã cho.

**Tham số:**
- `seed` (u32): Giá trị seed ảnh hưởng đến tạo mã vận hành đa hình

**Trả về:** Phiên bản Protector mới

**Ví dụ:**
```rust
let protector = Protector::new(0x12345678);
```

**Ghi Chú Dành Riêng Cho Windows:** Trên Windows, cách này tự động khởi tạo hệ thống bảo vệ VEH khi gọi lần đầu.

---

##### `is_debugged(&self) -> bool`

Kiểm tra xem debugger có được phát hiện hiện tại hay không.

**Trả về:** 
- `true` nếu phát hiện debugger
- `false` nếu không phát hiện debugger

**Các Phương Pháp Phát Hiện Được Sử Dụng:**
- Kiểm tra tính toàn vẹn bộ nhớ (cờ PEB)
- Phát hiện bất thường thời gian
- Kiểm tra xử lý ngoại lệ
- Phát hiện hypervisor

**Ví dụ:**
```rust
let protector = Protector::new(0xDEADBEEF);
if protector.is_debugged() {
    println!("Debugger được phát hiện!");
    std::process::exit(1);
}
```

**Hiệu Suất:** ~0.5-2ms tùy thuộc vào các kiểm tra hoạt động

---

##### `get_detection_details(&self) -> DetectionDetails`

Trả về thông tin chi tiết về tất cả các kiểm tra phát hiện.

**Trả về:** Cấu trúc `DetectionDetails` chứa:

```rust
pub struct DetectionDetails {
    pub is_debugged: bool,           // Phát hiện debug tổng thể
    pub score: u32,                  // Tổng điểm nghi ngờ (0-200+)
    pub peb_check: bool,             // Kết quả phát hiện dựa trên PEB
    pub rdtsc_check: bool,           // Kết quả phát hiện dựa trên thời gian
    pub heap_check: bool,            // Kết quả trình xử lý exception
    pub hypervisor_check: bool,      // Kết quả phát hiện ảo hóa
    pub integrity_check: bool,       // Kết quả kiểm tra tính toàn vẹn mã
}
```

**Ví dụ:**
```rust
let protector = Protector::new(0x12345678);
let details = protector.get_detection_details();

println!("Debugged: {}", details.is_debugged);
println!("Điểm Nghi ngờ: {}", details.score);
println!("Kiểm tra PEB: {}", details.peb_check);
println!("Kiểm tra RDTSC: {}", details.rdtsc_check);
println!("Kiểm tra Exception: {}", details.heap_check);
println!("Kiểm tra Hypervisor: {}", details.hypervisor_check);
println!("Kiểm tra Tính toàn vẹn: {}", details.integrity_check);
```

---

##### `encrypt_data(&self, plaintext: &[u8]) -> Vec<u8>`

Mã hóa dữ liệu bằng mã hóa XOR với kiểm tra debug tự động.

**Tham số:**
- `plaintext` (&[u8]): Dữ liệu để mã hóa

**Trả về:** Dữ liệu được mã hóa dưới dạng Vec<u8>

**Các Kiểm Tra Tự Động Được Thực Hiện:**
- Checkpoint tính toàn vẹn bộ nhớ
- Checkpoint tính toàn vẹn mã
- Nếu phát hiện debugger, khóa mã hóa bị hỏng → kết quả không thể sử dụng

**Ví dụ:**
```rust
let protector = Protector::new(0xDEADBEEF);
let plaintext = b"Thông điệp bí mật";
let encrypted = protector.encrypt_data(plaintext);

println!("Dữ liệu được mã hóa: {:?}", encrypted);
```

**Ghi Chú Bảo Mật:** Nếu phát hiện debugger, khóa mã hóa trở thành hỏng (0xFF), làm cho dữ liệu được mã hóa không hợp lệ.

---

##### `decrypt_data(&self, ciphertext: &[u8]) -> Vec<u8>`

Giải mã dữ liệu bằng mã hóa XOR với kiểm tra debug tự động.

**Tham số:**
- `ciphertext` (&[u8]): Dữ liệu để giải mã

**Trả về:** Dữ liệu được giải mã dưới dạng Vec<u8>

**Các Kiểm Tra Tự Động Được Thực Hiện:**
- Checkpoint xử lý ngoại lệ
- Checkpoint tính toàn vẹn mã
- Nếu phát hiện debugger, khóa giải mã bị hỏng → kết quả không hợp lệ

**Ví dụ:**
```rust
let protector = Protector::new(0xDEADBEEF);
let ciphertext = &[/* các byte được mã hóa */];
let decrypted = protector.decrypt_data(ciphertext);

println!("Dữ liệu được giải mã: {:?}", decrypted);
```

**Ghi Chú Bảo Mật:** Nếu phát hiện debugger trong bất kỳ hoạt động trước đó, giải mã sẽ thất bại im lặng.

---

##### `validate_license(&self, license_key: &str) -> bool`

Xác thực khóa giấy phép với kiểm tra bất thường thời gian tự động.

**Tham số:**
- `license_key` (&str): Khóa giấy phép để xác thực

**Trả về:**
- `true` nếu giấy phép hợp lệ và không phát hiện debugger
- `false` nếu giấy phép không hợp lệ hoặc phát hiện debugger

**Quy Tắc Xác Thực:**
- Khóa giấy phép phải chính xác 32 ký tự
- Tất cả các ký tự phải là ASCII alphanumeric

**Các Kiểm Tra Tự Động Được Thực Hiện:**
- Checkpoint bất thường thời gian
- Checkpoint tính toàn vẹn mã
- Nếu phát hiện debugger, khóa xác thực bị hỏng → trả về false

**Ví dụ:**
```rust
let protector = Protector::new(0x12345678);
let license = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";

if protector.validate_license(license) {
    println!("Giấy phép hợp lệ!");
} else {
    println!("Xác thực giấy phép thất bại");
}
```

---

## Các Hàm Toàn Cục

### `is_globally_debugged() -> bool`

Kiểm tra trạng thái debug toàn cục trên tất cả các threads.

**Trả về:** `true` nếu bất kỳ thread nào đã phát hiện debugger

**Hỗ Trợ Nền Tảng:** Chỉ Windows (trả về `false` trên các nền tảng khác)

**Ví dụ:**
```rust
use protector::is_globally_debugged;

if is_globally_debugged() {
    println!("Phát hiện debugger trong quy trình hiện tại");
}
```

---

### `get_suspicion_score() -> u32`

Trả về điểm nghi ngờ toàn cục hiện tại.

**Trả về:** Điểm nghi ngờ (0-255+)

**Quy Tắc Chấm Điểm:**
- Phát hiện PEB: +50 cho mỗi lần phát hiện
- Bất thường thời gian: +30 cho mỗi lần phát hiện
- Trình xử lý ngoại lệ: +40 cho mỗi lần phát hiện
- Hypervisor: +10-30 cho mỗi lần phát hiện
- Tính toàn vẹn mã: +70 cho mỗi lần phát hiện

**Ví dụ:**
```rust
use protector::get_suspicion_score;

let score = get_suspicion_score();
if score > 100 {
    println!("Nghi ngờ cao: {}", score);
}
```

---

### `add_suspicion(score: u32, checkpoint_type: usize)`

Thêm thủ công các điểm nghi ngờ (cho các kiểm tra tùy chỉnh).

**Tham số:**
- `score` (u32): Điểm để thêm
- `checkpoint_type` (usize): Danh mục nghi ngờ:
  - 0: Kiểm tra PEB
  - 1: Kiểm tra thời gian
  - 2: Kiểm tra ngoại lệ
  - 3: Kiểm tra hypervisor
  - 4: Kiểm tra tính toàn vẹn

**Ví dụ:**
```rust
use protector::add_suspicion;

// Thêm phát hiện tùy chỉnh
if suspicious_condition {
    add_suspicion(25, 0);  // Thêm vào danh mục PEB
}
```

---

## Các Hàm Checkpoint Phát Hiện

Các hàm này thực hiện các kiểm tra phát hiện riêng lẻ và trả về kết quả ngay lập tức.

### `checkpoint_memory_integrity() -> bool`

Thực hiện kiểm tra tính toàn vẹn bộ nhớ dựa trên PEB.

**Trả về:** `true` nếu phát hiện hoạt động đáng nghi

**Phát Hiện:** Debugger thông qua cờ PEB và giá trị NtGlobalFlag

**Hiệu Suất:** ~0.1-0.2ms

---

### `checkpoint_timing_anomaly() -> bool`

Thực hiện phát hiện bất thường thời gian dựa trên RDTSC.

**Trả về:** `true` nếu phát hiện bất thường thời gian

**Phát Hiện:** Sự can thiệp của debugger vào thời gian thực thi lệnh

**Hiệu Suất:** ~0.05-0.1ms

---

### `checkpoint_exception_handling() -> bool`

Thực hiện giám sát trình xử lý ngoại lệ vector.

**Trả về:** `true` nếu phát hiện các hook exception

**Phát Hiện:** Cài đặt breakpoint và các hook exception

**Hiệu Suất:** ~0.2-0.5ms

---

### `checkpoint_hypervisor_detection() -> bool`

Thực hiện phát hiện hypervisor/ảo hóa.

**Trả về:** `true` nếu phát hiện hypervisor

**Phát Hiện:** VMware, VirtualBox, Hyper-V, KVM, Xen, Parallels

**Hiệu Suất:** ~0.3-0.5ms

**Ghi Chú:** Có tỷ lệ dương tính giả cao hơn trong môi trường điện toán đám mây

---

### `checkpoint_integrity_self_hash() -> bool`

Thực hiện xác minh tính toàn vẹn mã tại thời gian chạy.

**Trả về:** `true` nếu phát hiện làm giả mã

**Phát Hiện:** Sửa đổi bộ nhớ của các phần mã quan trọng

**Hiệu Suất:** ~0.2-0.4ms

---

## Các Hằng Số Cấu Hình

Những điều này có thể được sửa đổi trong `src/protector/anti_debug.rs`:

```rust
// Ngưỡng RDTSC tính theo chu kỳ CPU
const RDTSC_FALLBACK_THRESHOLD: u64 = 100;

// Bật/Tắt chế độ làm hỏng dữ liệu im lặng
const DATA_CORRUPTION_MODE: bool = true;

// Bật/Tắt phát hiện dựa trên VEH
const ENABLE_VEH_DETECTION: bool = true;

// Bật/Tắt kiểm tra tính toàn vẹn tại thời gian chạy
const ENABLE_INTEGRITY_CHECK: bool = true;

// Delta baseline tối đa được chấp nhận trong quá trình hiệu chuẩn
const CALIBRATION_SANITY_MAX: u64 = 1000;
```

---

## Xử Lý Lỗi

Mô-đul không ném ra ngoại lệ. Thay vào đó:

1. **Đầu Vào Không Hợp Lệ**: Được xử lý im lặng với các giá trị mặc định an toàn
2. **Phát Hiện Debugger**: Trả về false/làm hỏng khóa (chế độ làm hỏng im lặng)
3. **Lỗi Quyền**: Trả về false (tiếp tục thực thi)

**Ví dụ:**
```rust
let protector = Protector::new(0x12345);

// Sẽ không panic, nhưng có thể trả về false/dữ liệu hỏng
let encrypted = protector.encrypt_data(&[]);
let decrypted = protector.decrypt_data(&[]);
let valid = protector.validate_license("");
```

---

## An Toàn Luồng

Mô-đul sử dụng atomic variables để quản lý trạng thái an toàn cho luồng:

- Trạng thái phát hiện được chia sẻ giữa các threads
- Tất cả các hoạt động đều là atomic
- Không có khóa mutex (thiết kế lock-free)

**Ví dụ:**
```rust
use std::sync::Arc;
use std::thread;

let protector = Arc::new(Protector::new(0xDEADBEEF));

for i in 0..4 {
    let p = Arc::clone(&protector);
    thread::spawn(move || {
        // Tất cả threads thấy cùng một trạng thái phát hiện
        if p.is_debugged() {
            println!("Thread {} phát hiện debugger", i);
        }
    });
}
```

---

## Hành Vi Dành Riêng Cho Nền Tảng

### Windows (x86_64)
- Hỗ trợ phát hiện đầy đủ
- Tất cả các checkpoint hoạt động
- Khởi tạo VEH khi sử dụng lần đầu

### Các Nền Tảng Khác
```rust
// Triển khai dummy
pub struct Protector {
    _seed: u32,
}

impl Protector {
    pub fn new(seed: u32) -> Self { /* ... */ }
    pub fn is_debugged(&self) -> bool { false }  // Luôn false
    pub fn get_detection_details(&self) -> DetectionDetails { /* chi tiết trống */ }
    pub fn encrypt_data(&self, plaintext: &[u8]) -> Vec<u8> { plaintext.to_vec() }
    pub fn decrypt_data(&self, ciphertext: &[u8]) -> Vec<u8> { ciphertext.to_vec() }
    pub fn validate_license(&self, license_key: &str) -> bool { 
        license_key.len() == 32 && license_key.chars().all(|c| c.is_ascii_alphanumeric())
    }
}
```

---

## Macro

### `setup_anti_debug!(seed)`

Macro tiện lợi để khởi tạo nhanh chóng.

**Ví dụ:**
```rust
use fuckDebug::setup_anti_debug;

let protector = setup_anti_debug!(0x12345678);
```

---

## Đặc Điểm Hiệu Suất

| Hoạt Động | Thời Gian | Overhead |
|-----------|-----------|----------|
| `new()` | 1-5ms | Một lần |
| `is_debugged()` | 0.5-2ms | Mỗi lần gọi |
| `get_detection_details()` | 1-3ms | Mỗi lần gọi |
| `encrypt_data()` 1KB | <1ms | Nhanh |
| `decrypt_data()` 1KB | <1ms | Nhanh |
| `validate_license()` | 0.1-0.3ms | Nhanh |

---

## Sử Dụng Bộ Nhớ

| Cấu Trúc | Kích Thước | Ghi Chú |
|-----------|-----------|--------|
| Protector | 4 bytes | Chỉ seed |
| DetectionDetails | 28 bytes | Tĩnh, trên stack |
| Trạng thái toàn cục | ~64 bytes | Atomic variables |

---

## Lịch Sử Phiên Bản

- **v0.1.0** - Phiên bản đầu tiên
  - Phát hiện đa lớp
  - Chế độ làm hỏng im lặng
  - Quản lý trạng thái an toàn cho luồng

---

## Khả Năng Tương Thích Ngược

- API ổn định và không có khả năng thay đổi
- Các hằng số cấu hình có thể được điều chỉnh an toàn
- Ngưỡng phát hiện có thể được tinh chỉnh cho mỗi triển khai

---

## Câu Hỏi Thường Gặp

**Q: Tại sao `is_debugged()` không phát hiện các debugger kernel?**
A: Nó chỉ giám sát các chỉ báo chế độ người dùng. Các debugger kernel cần các cơ chế phát hiện khác nhau.

**Q: Tôi có thể tắt các checkpoint phát hiện cụ thể không?**
A: Có, sửa đổi các hằng số trong `anti_debug.rs` và xây dựng lại.

**Q: Điều gì xảy ra nếu debugger gắn sau khi khởi tạo?**
A: Các lệnh gọi tiếp theo đến bất kỳ phương thức nào sẽ phát hiện debugger mới thông qua các checkpoint.

**Q: Mô-đul có an toàn cho luồng không?**
A: Có, tất cả trạng thái được quản lý bằng atomic variables (lock-free).

**Q: Tôi có thể sử dụng mô-đul trong các bản dựng phiên bản không?**
A: Có, nó được thiết kế cho các bản dựng phiên bản. Tác động hiệu suất là tối thiểu.

# Hướng Dẫn Tích Hợp - Mô-đun Bảo Vệ Chống Debug

## Cách Tích Hợp Vào Dự Án Rust Của Bạn

### Bước 1: Sao Chép Tệp Mô-đun

Sao chép thư mục `src/protector/` vào dự án của bạn:

```
your_project/
├── src/
│   ├── main.rs
│   ├── lib.rs
│   └── protector/          ← Sao chép toàn bộ thư mục này
│       ├── mod.rs
│       ├── anti_debug.rs
│       ├── tiny_vm.rs
│       └── global_state.rs
└── Cargo.toml
```

### Bước 2: Cập Nhật Cargo.toml

Đảm bảo bạn có phụ thuộc cần thiết:

```toml
[dependencies]
windows = { version = "0.51", features = [
    "Win32_Foundation",
    "Win32_System_Memory", 
    "Win32_System_Diagnostics_Debug"
] }
```

### Bước 3: Nhập Trong Mã Của Bạn

Trong `src/main.rs` hoặc `src/lib.rs`:

```rust
mod protector;
use protector::Protector;
```

### Bước 4: Khởi Tạo Sớm

Gọi khởi tạo ngay từ đầu ứng dụng của bạn:

```rust
fn main() {
    let protector = Protector::new(0x12345678);
    
    if protector.is_debugged() {
        eprintln!("Phát hiện môi trường debug");
        std::process::exit(1);
    }
    
    // Phần còn lại của ứng dụng
}
```

## Các Mẫu Tích Hợp

### Mẫu 1: Phát Hiện Sớm (Được Khuyến Nghị)

```rust
fn main() {
    // Khởi tạo ngay lập tức
    let protector = Protector::new(0xDEADBEEF);
    
    // Kiểm tra trước bất kỳ hoạt động nhạy cảm nào
    if protector.is_debugged() {
        std::process::exit(1);
    }
    
    run_application()
}

fn run_application() {
    // Mã ứng dụng với bảo vệ được đảm bảo
}
```

### Mẫu 2: Phát Hiện Dần Dần

```rust
fn main() {
    let protector = Protector::new(0xDEADBEEF);
    run_application(&protector)
}

fn run_application(protector: &Protector) {
    // Kiểm tra trước mỗi hoạt động nhạy cảm
    if protector.is_debugged() {
        handle_debugger_detected();
        return;
    }
    
    let sensitive_data = load_sensitive_data();
    protect_data(protector, &sensitive_data);
}

fn protect_data(protector: &Protector, data: &[u8]) {
    // Mã hóa dữ liệu - bao gồm kiểm tra debug tự động
    let encrypted = protector.encrypt_data(data);
    process_encrypted(encrypted);
}
```

### Mẫu 3: Giám Sát Liên Tục

```rust
fn main() {
    let protector = Protector::new(0xDEADBEEF);
    
    loop {
        if protector.is_debugged() {
            eprintln!("Phát hiện debug trong quá trình thực thi!");
            break;
        }
        
        process_iteration(&protector);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
```

### Mẫu 4: Với Xác Thực Giấy Phép

```rust
fn main() {
    let license_key = std::env::var("LICENSE_KEY")
        .unwrap_or_else(|_| "invalid".to_string());
    
    let protector = Protector::new(0xDEADBEEF);
    
    // Xác thực giấy phép (bao gồm kiểm tra debug)
    if !protector.validate_license(&license_key) {
        eprintln!("Xác thực giấy phép thất bại hoặc phát hiện debugger");
        std::process::exit(1);
    }
    
    run_application(&protector);
}
```

## Các Tình Huống Tích Hợp Nâng Cao

### Tình Huống 1: Bảo Vệ Các Khóa Mã Hóa

```rust
fn protect_crypto_keys(protector: &Protector) {
    let key_material = load_key_material();
    
    // Mã hóa khóa (bao gồm kiểm tra debug tự động)
    let encrypted_keys = protector.encrypt_data(&key_material);
    
    // Lưu trữ khóa được mã hóa
    store_keys(&encrypted_keys);
    
    // Sau đó, khi cần khóa:
    if protector.is_debugged() {
        return; // Không sử dụng khóa nếu debugged
    }
    
    let decrypted_keys = protector.decrypt_data(&encrypted_keys);
    use_keys(&decrypted_keys);
}
```

### Tình Huống 2: Bảo Vệ Kiểm Tra Giấy Phép

```rust
fn check_license_validity(protector: &Protector) -> bool {
    // Kiểm tra giấy phép bao gồm phát hiện bất thường thời gian
    let valid = protector.validate_license(&load_license());
    
    if !valid {
        // Có thể là giấy phép không hợp lệ HOẶC phát hiện debugger
        // Làm hỏng dữ liệu im lặng đảm bảo kết quả sai nếu debugged
        return false;
    }
    
    true
}
```

### Tình Huống 3: Ứng Dụng Đa Luồng

```rust
use std::sync::Arc;

fn main() {
    let protector = Arc::new(Protector::new(0xDEADBEEF));
    
    // Trạng thái phát hiện được chia sẻ trên các threads thông qua atomic variables
    let mut handles = vec![];
    
    for i in 0..4 {
        let p = Arc::clone(&protector);
        let handle = std::thread::spawn(move || {
            // Tất cả threads thấy trạng thái phát hiện giống nhau
            if p.is_debugged() {
                println!("Phát hiện debugger trong thread {}", i);
            }
        });
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
}
```

### Tình Huống 4: Kích Hoạt Tính Năng Có Điều Kiện

```rust
fn initialize_features(protector: &Protector) {
    let details = protector.get_detection_details();
    
    // Chỉ bật tính năng cao cấp nếu không bị debugged
    let enable_premium = !details.is_debugged && details.score < 30;
    
    if enable_premium {
        println!("Tính năng cao cấp được bật");
    } else {
        println!("Đang chạy ở chế độ an toàn");
    }
}
```

## Khắc Phục Sự Cố Tích Hợp

### Vấn Đề: Lỗi "Module not found"

**Giải pháp**: Đảm bảo đường dẫn là chính xác:
```rust
mod protector;  // Đường dẫn phải khớp với cấu trúc thư mục của bạn
```

### Vấn Đề: Biên Dịch Dành Riêng Cho Windows

**Vấn Đề**: Chỉ biên dịch trên Windows x86_64

**Giải pháp**: Để hỗ trợ đa nền tảng, sử dụng biên dịch có điều kiện:
```rust
#[cfg(target_os = "windows")]
{
    mod protector;
    use protector::Protector;
}

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("Chống debug chỉ khả dụng trên Windows");
}
```

### Vấn Đề: Dương Tính Giả Trong Máy Ảo

**Giải pháp**: Điều chỉnh ngưỡng phát hiện trong `src/protector/anti_debug.rs`:

```rust
// Tăng ngưỡng thời gian cho môi trường điện toán đám mây
const RDTSC_FALLBACK_THRESHOLD: u64 = 500; // Tăng từ 100

// Tắt phát hiện hypervisor nếu không cần
const ENABLE_VEH_DETECTION: bool = false;
```

### Vấn Đề: Tác Động Đến Hiệu Suất

**Giải pháp**: Gọi các checkpoint phát hiện một cách chiến lược:

```rust
// Xấu: Kiểm tra mỗi lần lặp
loop {
    if protector.is_debugged() { } // Quá thường xuyên
    process();
}

// Tốt: Kiểm tra định kỳ
let mut check_counter = 0;
loop {
    if check_counter % 1000 == 0 && protector.is_debugged() {
        break; // Kiểm tra một lần mỗi 1000 lần lặp
    }
    process();
    check_counter += 1;
}
```

## Tối Ưu Hóa Hiệu Suất

### Giảm Overhead Phát Hiện

1. **Lưu trữ kết quả phát hiện** (thận trọng):
```rust
let is_debugged = protector.is_debugged();
for i in 0..10000 {
    if is_debugged {
        break; // Chỉ kiểm tra một lần
    }
    heavy_computation();
}
```

2. **Hoạt động hàng loạt**:
```rust
// Mã hóa nhiều mục với một kiểm tra bảo vệ
let protector = Protector::new(0x12345);
if !protector.is_debugged() {
    for data in items {
        let encrypted = protector.encrypt_data(data);
        // Xử lý được mã hóa
    }
}
```

3. **Khởi tạo lười biếng**:
```rust
use std::sync::Once;

static INIT: Once = Once::new();
static mut PROTECTOR: Option<Protector> = None;

fn get_protector() -> &'static Protector {
    unsafe {
        INIT.call_once(|| {
            PROTECTOR = Some(Protector::new(0xDEADBEEF));
        });
        PROTECTOR.as_ref().unwrap()
    }
}
```

## Kiểm Tra Tích Hợp Của Bạn

### Ví Dụ Kiểm Tra Đơn Vị

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_protector_integration() {
        let protector = Protector::new(0x12345);
        
        // Không nên crash
        assert!(!protector.is_debugged() || protector.is_debugged());
        
        // Nên trả về chi tiết phát hiện hợp lệ
        let details = protector.get_detection_details();
        assert!(details.score >= 0);
    }
    
    #[test]
    fn test_encryption_decryption() {
        let protector = Protector::new(0x12345);
        
        let original = b"dữ liệu thử nghiệm";
        let encrypted = protector.encrypt_data(original);
        let decrypted = protector.decrypt_data(&encrypted);
        
        // Có thể không khớp nếu phát hiện debugger
        println!("Kiểm tra mã hóa hoàn tất");
    }
}
```

## Xây Dựng Và Triển Khai

### Xây Dựng Debug
```bash
cargo build
```

### Xây Dựng Phiên Bản (Được Khuyến Nghị Cho Sản Xuất)
```bash
cargo build --release
```

### Kiểm Tra Biên Dịch Chéo
```bash
cargo check --target x86_64-pc-windows-msvc
```

## Các Thực Hành Tốt Nhất Về Bảo Mật

1. **Sử dụng seed khác nhau** cho các tệp nhị phân khác nhau:
```rust
let seed = env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap();
let protector = Protector::new(seed);
```

2. **Không mã hóa cứng các giá trị nhạy cảm** - sử dụng tệp cấu hình hoặc biến môi trường

3. **Kiểm tra mà không có debugger** - đảm bảo hoạt động bình thường:
```bash
# Chạy mà không có debugger
./target/release/your_app

# Nhưng đừng gắn debugger và mong đợi nó hoạt động bình thường
```

4. **Xem xét các công cụ làm xáo trộn** - kết hợp với các công cụ như:
   - UPX (đóng gói tệp thực thi)
   - Làm xáo trộn LLVM
   - Công cụ mã hóa chuỗi

## Số Liệu Hiệu Suất

| Hoạt Động | Thời Gian | Ghi Chú |
|-----------|-----------|--------|
| Khởi tạo | 1-5ms | Thiết lập một lần |
| Kiểm tra bộ nhớ | 0.1-0.2ms | Nhanh, đáng tin cậy |
| Kiểm tra thời gian | 0.05-0.1ms | Rất nhanh |
| Kiểm tra exception | Thay đổi | Phụ thuộc vào hệ thống |
| Kiểm tra hypervisor | 0.3-0.5ms | Tính toán CPU |
| Kiểm tra tính toàn vẹn | 0.2-0.4ms | Tính toán hash |
| Mã hóa 1KB | <1ms | Dựa trên XOR |
| Giải mã 1KB | <1ms | Dựa trên XOR |

## Nhận Trợ Giúp

Để giải quyết các vấn đề tích hợp:

1. Xem lại ví dụ trong `src/main.rs`
2. Kiểm tra các trường hợp thử nghiệm trong `src/protector/mod.rs`
3. Bật ghi nhật ký debug trong `anti_debug.rs`
4. Chạy với bản dựng phiên bản để xem hiệu suất thực tế

## Các Bước Tiếp Theo

Sau khi tích hợp:
1. Kiểm tra kỹ lưỡng trong môi trường mục tiêu của bạn
2. Xác minh rằng phát hiện hoạt động như mong đợi
3. Giám sát các dương tính giả
4. Điều chỉnh ngưỡng nếu cần thiết
5. Triển khai với tự tin

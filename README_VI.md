# Mô-đun Bảo Vệ Chống Debug

**Một giải pháp bảo vệ chống debug toàn diện, có thể tích hợp dễ dàng cho các ứng dụng Rust trên Windows với phát hiện dựa trên VM và cơ chế làm hỏng dữ liệu im lặng.**

## Tổng Quan

Đây là thư viện bảo vệ chống debug nâng cao được thiết kế để phát hiện và trung hòa các công cụ debug trong môi trường Windows. Nó sử dụng nhiều cơ chế phát hiện tinh vi bao gồm:

- **Phát hiện dựa trên Máy ảo (VM)**: Thực thi bytecode đa hình để kiểm tra tính toàn vẹn bộ nhớ
- **Phát hiện Bất thường Về Thời gian**: Phân tích thời gian dựa trên RDTSC để phát hiện sự can thiệp của debugger
- **Phân tích PEB**: Kiểm tra trực tiếp cấu trúc Process Environment Block để tìm cờ debug
- **Phát hiện Hypervisor**: Phát hiện đa lớp cho máy ảo và môi trường điện toán đám mây
- **Xác minh Tính Toàn vẹn của Code**: Kiểm tra tính toàn vẹn mã nguồn tại thời gian chạy
- **Hệ Thống Trạng Thái Phân Tán**: Sử dụng atomic variables để theo dõi phát hiện trên nhiều threads
- **Làm Hỏng Dữ liệu Im Lặng**: Khi phát hiện debugger, các hoạt động nhạy cảm bị làm hỏng thay vì thoát

## Tính Năng Chính

### 🛡️ Phát hiện Đa Lớp
- **Checkpoint Tính Toàn vẹn Bộ nhớ**: Phát hiện debugger thông qua cờ PEB và giá trị NtGlobalFlag
- **Checkpoint Bất thường Về Thời gian**: Sử dụng lệnh RDTSC để đo lường các bất thường trong thời gian thực thi
- **Checkpoint Xử lý Ngoại lệ**: Giám sát các trình xử lý ngoại lệ vector để phát hiện breakpoint
- **Checkpoint Phát hiện Hypervisor**: Xác định môi trường ảo hóa bằng phân tích CPUID
- **Checkpoint Tính Toàn vẹn**: Xác minh tại thời gian chạy các phần mã nguồn quan trọng

### 🔐 Tính Năng Chống Phân Tích
- **Mã Vận Hành Đa Hình**: Các lệnh TinyVM thay đổi trong mỗi lần build do seed duy nhất
- **Chuỗi được Mã hóa XOR**: Các chuỗi quan trọng được mã hóa để ngăn chặn phân tích tĩnh
- **Vị ngữ Opaque**: Luồng mã bao gồm các nhánh điều kiện xuất hiện phức tạp nhưng được xác định toán học
- **Trạng Thái Phát hiện Phân Tán**: Sử dụng atomic variables để theo dõi phát hiện trên các threads

### 🎯 Phản Ứng Thông Minh
- **Hệ Thống Đánh Giá Nghi Ngờ**: Tích lũy dần nghi ngờ thay vì phát hiện ngay lập tức
- **Ngưỡng Dựa trên Danh Mục**: Các loại phát hiện khác nhau có yêu cầu độ tin cậy khác nhau
- **Chế Độ Làm Hỏng Dữ liệu Im Lặng**: Thay vì crash, các hoạt động nhạy cảm tạo ra kết quả bị làm hỏng
- **Trạng Thái Liên Tục**: Sau khi phát hiện debugger, trạng thái vẫn được thiết lập vĩnh viễn

## Hỗ Trợ Nền Tảng

- **Chính**: Windows x86_64 (hỗ trợ đầy đủ)
- **Phụ**: Các nền tảng khác có các triển khai dummy luôn trả về false

## Cài Đặt

### Như Một Mô-đun

1. Sao chép thư mục `src/protector/` vào dự án Rust của bạn
2. Thêm vào `lib.rs` hoặc `main.rs`:

```rust
mod protector;
use protector::Protector;
```

### Như Một Dependency (Cargo)

Thêm vào `Cargo.toml`:

```toml
[dependencies]
windows = { version = "0.51", features = ["Win32_Foundation", "Win32_System_Memory", "Win32_System_Diagnostics_Debug"] }
```

## Bắt Đầu Nhanh

### Cách Sử Dụng Cơ Bản

```rust
use protector::Protector;

fn main() {
    // Khởi tạo protector với một giá trị seed
    let protector = Protector::new(0x12345678);
    
    // Kiểm tra xem debugger có được phát hiện không
    if protector.is_debugged() {
        eprintln!("Debugger đã bị phát hiện!");
        std::process::exit(1);
    }
    
    // Mã ứng dụng của bạn tại đây
    println!("An toàn khỏi các debugger!");
}
```

### Cách Sử Dụng Nâng Cao Với Thông Tin Chi Tiết Phát hiện

```rust
use protector::Protector;

fn main() {
    let protector = Protector::new(0x12345678);
    
    // Lấy thông tin chi tiết phát hiện
    let details = protector.get_detection_details();
    
    println!("Debugger phát hiện: {}", details.is_debugged);
    println!("Điểm Nghi ngờ: {}", details.score);
    println!("Kết quả Kiểm tra PEB: {}", details.peb_check);
    println!("Kết quả Kiểm tra RDTSC: {}", details.rdtsc_check);
    println!("Kiểm tra Trình xử lý Exception: {}", details.heap_check);
    println!("Kiểm tra Hypervisor: {}", details.hypervisor_check);
    println!("Kiểm tra Tính toàn vẹn: {}", details.integrity_check);
}
```

### Sử Dụng Mã hóa/Giải mã Với Bảo Vệ Nhúng

```rust
use protector::Protector;

fn main() {
    let protector = Protector::new(0x87654321);
    
    // Mã hóa dữ liệu (bao gồm kiểm tra chống debug tự động)
    let plaintext = b"Thông điệp bí mật";
    let encrypted = protector.encrypt_data(plaintext);
    
    // Nếu phát hiện debugger, dữ liệu sẽ bị làm hỏng trong quá trình mã hóa
    println!("Độ dài dữ liệu được mã hóa: {}", encrypted.len());
    
    // Giải mã dữ liệu (bao gồm kiểm tra chống debug tự động)
    let decrypted = protector.decrypt_data(&encrypted);
    
    // Nếu phát hiện debugger trước đó, giải mã sẽ thất bại im lặng
}
```

### Xác Thực Giấy Phép Với Chống Debug

```rust
use protector::Protector;

fn main() {
    let protector = Protector::new(0xDEADBEEF);
    
    let license_key = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6";
    
    // Xác thực giấy phép bao gồm kiểm tra bất thường về thời gian
    if protector.validate_license(license_key) {
        println!("Giấy phép hợp lệ!");
    } else {
        // Có thể là giấy phép không hợp lệ hoặc phát hiện debugger
        println!("Xác thực giấy phép thất bại");
    }
}
```

## Cấu Hình

Hành vi của mô-đun có thể được tùy chỉnh bằng cách sửa đổi các hằng số trong `src/protector/anti_debug.rs`:

```rust
/// Ngưỡng fallback hardcoded cho RDTSC (tính theo chu kỳ CPU)
const RDTSC_FALLBACK_THRESHOLD: u64 = 100;

/// Chế Độ Làm Hỏng Dữ liệu: Khi được bật, đầu ra bị làm hỏng im lặng thay vì thoát
const DATA_CORRUPTION_MODE: bool = true;

/// Phát hiện VEH: Sử dụng Trình xử lý Ngoại lệ Vector để phát hiện breakpoint
const ENABLE_VEH_DETECTION: bool = true;

/// Kiểm tra Tính Toàn vẹn: Bật xác minh tính toàn vẹn mã nguồn tại thời gian chạy
const ENABLE_INTEGRITY_CHECK: bool = true;
```

## Các Checkpoint Phát hiện

### 1. Checkpoint Tính Toàn vẹn Bộ nhớ
- **Phát hiện gì**: Debugger thông qua cờ PEB và NtGlobalFlag
- **Cách hoạt động**: Sử dụng TinyVM để thực thi bytecode đa hình đọc cấu trúc PEB
- **Điểm Nghi ngờ Được Thêm**: 50 điểm
- **Độ Tin cậy**: Rất cao (đáng tin cậy trên tất cả các phiên bản Windows)

### 2. Checkpoint Bất thường Về Thời gian
- **Phát hiện gì**: Sự can thiệp của debugger vào thực thi lệnh
- **Cách hoạt động**: Đo lường chu kỳ RDTSC giữa hai dấu thời gian
- **Điểm Nghi ngờ Được Thêm**: 30 điểm
- **Độ Tin cậy**: Cao (nhưng có thể có dương tính giả trên các hệ thống tải nặng)

### 3. Checkpoint Xử lý Ngoại lệ
- **Phát hiện gì**: Breakpoint phần cứng và các hook exception
- **Cách hoạt động**: Giám sát các trình xử lý ngoại lệ vector
- **Điểm Nghi ngờ Được Thêm**: 40 điểm
- **Độ Tin cậy**: Trung bình (phụ thuộc vào cách triển khai debugger)

### 4. Checkpoint Phát hiện Hypervisor
- **Phát hiện gì**: Máy ảo và các môi trường điện toán đám mây
- **Cách hoạt động**: Sử dụng CPUID để phát hiện sự hiện diện hypervisor và chuỗi nhãn hiệu
- **Điểm Nghi ngờ Được Thêm**: 10-30 điểm (thay đổi)
- **Độ Tin cậy**: Trung bình (tỷ lệ dương tính giả cao trong môi trường điện toán đám mây)

### 5. Checkpoint Tính Toàn vẹn
- **Phát hiện gì**: Làm giả mã nguồn và sửa đổi phần mã
- **Cách hoạt động**: Tính toán hash các phần mã nguồn quan trọng
- **Điểm Nghi ngờ Được Thêm**: 70 điểm
- **Độ Tin cậy**: Rất cao (phát hiện các sửa đổi mã thực tế)

## Hệ Thống Đánh Giá Nghi Ngờ

Mô-đun sử dụng hệ thống chấm điểm thay vì phát hiện ngay lập tức:

```
Quy Tắc Tổng Điểm Nghi Ngờ:
- Kiểm tra PEB: Ngưỡng 40 điểm
- Kiểm tra Thời gian: Ngưỡng 60 điểm
- Kiểm tra Exception: Ngưỡng 50 điểm
- Kiểm tra Hypervisor: Ngưỡng 30 điểm
- Kiểm tra Tính toàn vẹn: Ngưỡng 35 điểm
- Ngưỡng Toàn cầu: 100 điểm

Khi bất kỳ danh mục nào vượt quá ngưỡng của nó HOẶC điểm toàn cầu vượt quá 100,
mô-đul đặt cờ debug và làm hỏng khóa mã hóa.
```

## Hành Động Đầu Ra

Khi phát hiện debugger, mô-đul KHÔNG crash hoặc thoát. Thay vào đó:

1. **Làm Hỏng Khóa Mã hóa**: Khóa mã hóa được đặt thành `0xFF`
2. **Làm Hỏng Khóa VM**: Khóa máy ảo được đặt thành `0x00`
3. **Thất Bại Im Lặng**: Dữ liệu được mã hóa/giải mã trở nên không sử dụng được
4. **Phát hiện Liên Tục**: Cờ debug vẫn được đặt vĩnh viễn

## Phần Trong Cùng của TinyVM

Mô-đun bao gồm một máy ảo nhẹ để thực thi được che giấu:

### Hoạt Động Được Hỗ Trợ
- **Hoạt Động Stack**: PUSH, POP, DUP, SWAP
- **Hoạt Động Bộ nhớ**: READ_MEM_U8, READ_MEM_U32, READ_MEM_U64
- **Số học**: ADD, SUB, XOR, AND, OR, NOT, SHL, SHR
- **Luồng Điều khiển**: JUMP, JZ, JNZ, CALL, RET, EXIT
- **Hoạt Động CPU**: RDTSC, CPUID, IN_PORT, OUT_PORT
- **Hoạt Động Hệ thống**: READ_GS_OFFSET (để truy cập PEB)

### Tính Đa Hình
Mỗi mã vận hành lệnh được tạo động tại thời gian compile bằng cách sử dụng:
```rust
macro_rules! auto_op {
    ($base:expr) => {
        (($base as u8).wrapping_add(BUILD_SEED as u8))
    };
}
```

Nơi `BUILD_SEED` được tính từ tên gói, đường dẫn tệp và thư mục manifest.

## Các Xem Xét Về Bảo Mật

### Điểm Mạnh
- ✅ Nhiều cơ chế phát hiện độc lập
- ✅ Trạng thái phân tán trên các threads
- ✅ Tạo mã đa hình
- ✅ Chế độ làm hỏng dữ liệu im lặng (kẻ tấn công không biết phát hiện đã xảy ra)
- ✅ Xác minh tính toàn vẹn tại thời gian chạy

### Hạn Chế
- ⚠️ Chỉ phát hiện các debugger ở chế độ người dùng
- ⚠️ Các debugger ở chế độ kernel có thể vượt qua phát hiện
- ⚠️ Có thể có dương tính giả trong các môi trường ảo hóa nặng
- ⚠️ Những kẻ tấn công lành nghề có kiến thức hệ thống sâu sắc có thể vượt qua

## Tác Động Về Hiệu Suất

- **Khởi tạo**: ~1-5ms cho thiết lập lần đầu
- **Checkpoint Phát hiện**: ~0.1-0.5ms mỗi lần gọi checkpoint
- **Overhead Bộ nhớ**: ~1-2KB cho các cấu trúc trạng thái
- **Mã hóa/Giải mã**: Giống như mã hóa XOR tiêu chuẩn (rất nhanh)

## Khắc Phục Sự Cố

### Dương Tính Giả

Nếu bạn gặp "debugger phát hiện" trong các triển khai hợp pháp:

1. **Trong Máy ảo**: Điều chỉnh ngưỡng phát hiện hypervisor
2. **Trên Phần cứng Chậm**: Tăng `RDTSC_FALLBACK_THRESHOLD`
3. **Trên Máy chủ Bận**: Tắt `ENABLE_VEH_DETECTION`

### Không Phát hiện Debugger

Nếu các debugger không bị bắt:

1. Đảm bảo bạn đang chạy trên Windows x86_64
2. Kiểm tra xem protector có được khởi tạo sớm trong `main()` không
3. Xác minh tất cả các checkpoint phát hiện được gọi
4. Thử giảm các ngưỡng phát hiện

## Biên Dịch

```bash
# Xây dựng ở chế độ debug
cargo build

# Xây dựng phiên bản (tối ưu hóa)
cargo build --release

# Chạy các bài kiểm tra
cargo test

# Xây dựng sạch
cargo clean && cargo build
```

## Cấu Trúc Tệp

```
src/
├── main.rs                          # Ví dụ sử dụng và thử nghiệm
├── protector/
│   ├── mod.rs                       # Định nghĩa mô-đun và API công khai
│   ├── anti_debug.rs               # Các checkpoint phát hiện và logic
│   ├── tiny_vm.rs                  # Triển khai máy ảo
│   └── global_state.rs             # Quản lý trạng thái Atomic
├── build.rs                         # Kịch bản xây dựng
└── Cargo.toml                       # Các phụ thuộc
```

## Giấy Phép

Dự án này được thiết kế cho mục đích nghiên cứu bảo mật và phần mềm được bảo vệ. Việc sử dụng tuân theo các luật và quy định địa phương.

## Tài Liệu Tham Khảo

- Microsoft Windows Internals
- Tài Liệu Cấu Trúc PEB
- Tài Liệu Tham Khảo Lệnh CPUID
- Kỹ Thuật Phòng Chống Timing Attack

## Hỗ Trợ

Để giải quyết các vấn đề, câu hỏi hoặc đóng góp:

1. Kiểm tra [Tài Liệu](README.md) (phiên bản tiếng Anh)
2. Xem lại mã ví dụ trong `src/main.rs`
3. Kiểm tra các trường hợp thử nghiệm trong `src/protector/mod.rs`

---

**Lưu ý**: Thư viện này liên tục phát triển. Luôn kiểm tra kỹ lưỡng trong môi trường mục tiêu của bạn trước khi triển khai sản xuất.

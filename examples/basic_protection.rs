use fdebug::protector::setup_anti_debug;

fn main() {
    // 1. Khởi tạo protector với seed (thường lấy từ build-time entropy)
    let seed = 0x1337BEEF;
    let protector = setup_anti_debug!(seed);

    println!("Hệ thống đang chạy trong chế độ bảo vệ...");

    // 2. Kiểm tra trạng thái bảo vệ cơ bản (không khuyến khích dùng trực tiếp is_debugged)
    let details = protector.get_detection_details();
    
    if details.score > 0 {
        println!("Cảnh báo: Phát hiện dấu hiệu nghi vấn (Score: {})", details.score);
    }

    // 3. Thực hiện Business Logic bình thường
    // Nếu có debugger, các tính toán nhạy cảm tiếp theo sẽ tự động bị hỏng
    do_important_work(&protector);
}

fn do_important_work(_protector: &fdebug::protector::Protector) {
    println!("Đang thực hiện các tác vụ nhạy cảm...");
}

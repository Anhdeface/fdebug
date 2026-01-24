/*
HƯỚNG DẪN THÊM OPCODE MỚI VÀO TINYVM (tiny_vm.rs)

Nhiệm vụ: Thêm Opcode 'OP_CHECK_TIMESTAMP' để kiểm tra thời gian thực thi của một block code.
*/

// BƯỚC 1: Thêm vào enum VmOp
// pub enum VmOp {
//     ...
//     OP_CHECK_TIMESTAMP = auto_op!(0xAA), 
// }

// BƯỚC 2: Thêm state xử lý trong hàm vm_execute
// const STATE_HANDLE_OP_CHECK_TIMESTAMP: u32 = 0x9999AAAA;

// BƯỚC 3: Implement logic trong match state
/*
    s if opaque_predicate_eq_u32(s, STATE_HANDLE_OP_CHECK_TIMESTAMP) => {
        vm.vip += 1;
        let start_time = vm.pop();
        let current_time = get_rdtsc(); // Giả định hàm lấy rdtsc
        
        let delta = current_time - start_time;
        if delta > 100000 { // Nếu quá chậm (debugger breakpoint)
            add_suspicion(DetectionSeverity::High);
            vm.push(0); // Trả về thất bại
        } else {
            vm.push(1); // Trả về thành công
        }
        state = STATE_CONTINUE_LOOP;
    }
*/

fn main() {
    println!("Mẫu code này là hướng dẫn Technical cho việc mở rộng TinyVM.");
    println!("Xem comment trong file để biết chi tiết các bước thực hiện.");
}

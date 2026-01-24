use fdebug::protector::{setup_anti_debug, CoupledLogic, Corruptible};

struct FinancialReport {
    revenue: f64,
    is_valid: bool,
}

// Triển khai Trait Corruptible để cho phép Silent Corruption
impl Corruptible for FinancialReport {
    fn corrupt_if_needed(self, token: u64) -> Self {
        if token % 7 == 0 { // Token hỏng sẽ dẫn đến corruption
            FinancialReport {
                revenue: self.revenue * 0.5, // Giảm 50% doanh thu một cách bí ẩn
                is_valid: false,
            }
        } else {
            self
        }
    }
}

fn main() {
    let protector = setup_anti_debug!(12345);

    // Sử dụng run_coupled để bảo vệ logic tính toán tài chính
    let report = protector.run_coupled(|token| {
        // Logic tính toán thực tế nhận vào một 'token' bảo mật
        // Nếu môi trường sạch, token sẽ hợp lệ. Nếu có debugger, token là rác.
        let base_revenue = 1000000.0;
        
        FinancialReport {
            revenue: base_revenue + (token as f64 * 0.0001), 
            is_valid: true,
        }
    });

    println!("Report Revenue: {}", report.revenue);
    println!("Report Legitimacy: {}", report.is_valid);
}

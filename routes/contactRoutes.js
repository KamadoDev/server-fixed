const express = require("express");
const { ContactModel } = require("../models/ContactModel");
const { verifyToken } = require("../helper/authHelpers");
const router = express.Router();

// API GET để lấy thông tin liên hệ với phân trang
router.get("/", async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1; // Nếu không có page, mặc định là 1
    const perPage = 5; // Số lượng item mỗi trang

    if (req.query.page) {
      // Nếu có tham số page, thực hiện phân trang
      const totalPosts = await ContactModel.countDocuments();
      const totalPages = Math.ceil(totalPosts / perPage);

      if (page > totalPages) {
        return res.status(404).json({
          success: false,
          message: "Page not found",
        });
      }

      const contacts = await ContactModel.find()
        .skip((page - 1) * perPage) // Bỏ qua các mục đã hiển thị trên các trang trước
        .limit(perPage) // Giới hạn số lượng mục trên mỗi trang
        .populate("userId", "fullName phone email") // Liên kết với bảng User và chỉ lấy trường fullName, phone, email
        .exec();

      if (!contacts || contacts.length === 0) {
        return res.status(404).json({
          success: true,
          message: "No contacts found",
        });
      }

      return res.status(200).json({
        success: true,
        contacts,
        totalPages: totalPages,
        currentPage: page,
        totalItems: totalPosts,
        perPage: perPage,
      });
    } else {
      // Nếu không có tham số page, trả về tất cả danh mục
      const contacts = await ContactModel.find().populate(
        "userId",
        "fullName phone email "
      ); // Liên kết và lấy thông tin người dùng

      if (!contacts || contacts.length === 0) {
        return res.status(404).json({
          success: true,
          message: "No contacts found",
        });
      }

      return res.status(200).json({
        success: true,
        contacts,
      });
    }
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message || "An error occurred while fetching contacts",
    });
  }
});

// API nhận thông tin liên hệ và lưu vào MongoDB
router.post("/create", verifyToken, async (req, res) => {
  const { emailOrPhone, message, userId } = req.body; // Lấy userId từ body

  // Kiểm tra xem tất cả các trường đã có dữ liệu hay chưa
  if (!emailOrPhone || !message || !userId) {
    return res
      .status(400)
      .json({ success: false, message: "Vui lòng cung cấp đầy đủ thông tin." });
  }

  try {
    // Tạo một đối tượng mới từ model Contact
    const newContact = new ContactModel({
      emailOrPhone,
      message,
      userId, // Lưu userId vào thông tin liên hệ
    });

    // Lưu thông tin vào MongoDB
    await newContact.save();

    res
      .status(201)
      .json({ success: true, message: "Thông tin đã được gửi thành công." });
  } catch (error) {
    console.error("Lỗi khi lưu thông tin liên hệ:", error);
    res
      .status(500)
      .json({ success: false, message: "Lỗi server. Vui lòng thử lại." });
  }
});

// API DELETE: Xóa một Contact theo ID
router.delete("/:id", async (req, res) => {
  const contactId = req.params.id;

  try {
    // Tìm và xóa Contact dựa trên ID
    const deletedContact = await ContactModel.findByIdAndDelete(contactId);

    // Kiểm tra nếu không tìm thấy Contact để xóa
    if (!deletedContact) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy thông tin liên hệ để xóa.",
      });
    }

    // Trả về phản hồi khi xóa thành công
    return res.status(200).json({
      success: true,
      message: "Thông tin liên hệ đã được xóa thành công.",
    });
  } catch (err) {
    console.error("Lỗi khi xóa thông tin liên hệ:", err);
    return res.status(500).json({
      success: false,
      message: "Lỗi server. Vui lòng thử lại.",
    });
  }
});

module.exports = router;

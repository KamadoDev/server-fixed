const express = require("express");
const {
  isValidPhone,
  verifyToken,
  checkAdminOrOwner,
} = require("../helper/authHelpers");
const { OrderModel } = require("../models/OrderModel");
const { CartModel } = require("../models/CartModel"); // Import CartModel
const router = express.Router();

const { validateOrder } = require("../middlewares/validate");


// API lấy danh sách đơn hàng với phân trang
router.get("/", verifyToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1; // Nếu không có page, mặc định là 1
    const perPage = 5; // Số lượng đơn hàng mỗi trang

    const totalOrders = await OrderModel.countDocuments(); // Tổng số đơn hàng
    const totalPages = Math.ceil(totalOrders / perPage); // Tổng số trang

    if (page > totalPages) {
      return res.status(404).json({
        success: false,
        message: "Page not found",
      });
    }

    const orders = await OrderModel.find()
      .sort({ createdAt: -1 }) // Sắp xếp đơn hàng theo thời gian mới nhất
      .skip((page - 1) * perPage) // Bỏ qua các đơn hàng của trang trước
      .limit(perPage) // Lấy số lượng đơn hàng theo mỗi trang
      .exec();

    if (!orders || orders.length === 0) {
      return res.status(404).json({
        success: false,
        message: "No orders found",
      });
    }

    return res.status(200).json({
      success: true,
      orders,
      totalPages,
      currentPage: page,
      totalItems: totalOrders,
      perPage,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      success: false,
      message: "An error occurred while fetching orders",
      error: err.message,
    });
  }
});

router.get("/completed-orders", verifyToken, async (req, res) => {
  try {
    // Đếm tổng số đơn hàng có trạng thái "Completed"
    const completedOrdersCount = await OrderModel.countDocuments({
      status: "Completed",
    });

    return res.status(200).json({
      success: true,
      totalCompletedOrders: completedOrdersCount,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      success: false,
      message: "An error occurred while fetching completed orders count",
      error: err.message,
    });
  }
});

// API Get Order by ID
router.get("/item/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Tìm đơn hàng theo ID
    const order = await OrderModel.findById(id);

    if (!order) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy đơn hàng",
      });
    }

    // Trả về chi tiết đơn hàng
    res.status(200).json({
      success: true,
      message: "Lấy thông tin đơn hàng thành công",
      order,
    });
  } catch (error) {
    console.error("Lỗi khi lấy đơn hàng:", error);
    res.status(500).json({
      success: false,
      message: "Lỗi máy chủ nội bộ",
      error: error.message,
    });
  }
});

router.get("/:userId", verifyToken, async (req, res) => {
  try {
    // Lấy userId từ tham số trong URL
    const { userId } = req.params;

    // Kiểm tra xem người dùng đã xác thực có trùng với userId trong URL không (kiểm tra bảo mật tùy chọn)
    if (req.user.id !== userId) {
      return res.status(403).json({
        status: false,
        message: "Truy cập không được phép",
        type: "error",
      });
    }

    // Lấy danh sách đơn hàng của người dùng
    const orders = await OrderModel.find({ userId }).sort({
      createdAt: -1,
    });

    // Nếu không có đơn hàng hoặc giỏ hàng, trả về thông báo
    if (!orders.length) {
      return res.status(404).json({
        status: false,
        message: "Không tìm thấy đơn hàng của bạn",
        type: "error",
      });
    }

    // Trả về thông tin đơn hàng
    res.status(200).json({
      status: true,
      message: "Danh sách đơn hàng của bạn",
      type: "success",
      orders,
    });
  } catch (error) {
    console.error(error); // Ghi log lỗi để hỗ trợ debug
    res
      .status(500)
      .json({ message: "Lỗi máy chủ nội bộ", error: error.message });
  }
});

router.post("/create", validateOrder, verifyToken, async (req, res) => {
  try {
    const {
      fullName,
      phone,
      detail,
      notes,
      paymentMethod,
      userId,
      items,
      isVoucher,
      voucherCode,
      discountPercentage,
      appliedDate,
      province,
      provinceCode,
      district,
      districtCode,
      ward,
      wardCode,
      date,
      totalPrice,
    } = req.body;

    // Kiểm tra các trường dữ liệu bắt buộc
    const requiredFields = [
      { field: fullName, message: "Vui lòng điền tên người đặt hàng" },
      { field: phone, message: "Vui lòng nhập số điện người đặt hàng" },
      { field: province, message: "Vui lòng chọn tỉnh thành" },
      { field: district, message: "Vui lòng chọn huyện" },
      { field: ward, message: "Vui lòng chọn xã" },
      { field: detail, message: "Số nhà hoặc thôn làng nơi gần bạn nhất" },
      { field: paymentMethod, message: "Vui lòng chọn phương thức thanh toán" },
    ];

    for (const { field, message } of requiredFields) {
      if (!field && field !== 0) {
        return res
          .status(400)
          .json({ status: false, message: message, type: "error" });
      }
    }

    // Kiểm tra số điện thoại hợp lệ
    if (!isValidPhone(phone)) {
      return res.status(400).json({
        status: false,
        message: "Số điện thoại không hợp lệ.",
        type: "error",
      });
    }

    // Tạo đơn hàng mới
    const newOrder = new OrderModel({
      userId: userId,
      items: items,
      isVouched: isVoucher
        ? [
            {
              voucherCode: voucherCode,
              discountPercentage: discountPercentage,
              appliedDate: appliedDate,
            },
          ]
        : [],
      totalPrice: totalPrice,
      address: {
        province,
        provinceCode,
        district,
        districtCode,
        ward,
        wardCode,
        phone,
        detail,
        notes,
      },
      paymentMethod,
      orderDate: new Date(),
      status: "Pending",
    });

    // Lưu đơn hàng vào cơ sở dữ liệu
    const savedOrder = await newOrder.save();

    // Xóa giỏ hàng của người dùng sau khi đơn hàng được tạo
    await CartModel.findOneAndDelete({ userId: userId });

    // Trả về thông tin đơn hàng đã lưu
    res.status(201).json({
      status: true,
      message: "Đơn hàng đã được tạo thành công!",
      type: "success",
      order: savedOrder, // Gửi lại thông tin đơn hàng đã tạo
    });
  } catch (error) {
    return res.status(500).json({
      status: false,
      message: error.message || "An error occurred while creating the order",
      type: "error",
    });
  }
});

// Cập nhật đơn hàng
router.put("/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Kiểm tra sự tồn tại của đơn hàng
    const order = await OrderModel.findById(id);
    if (!order) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy đơn hàng",
      });
    }

    // Dữ liệu từ body
    const { status, paymentMethod, address } = req.body;

    console.log(status, paymentMethod, address);

    // Cập nhật thông tin
    if (status) order.status = status;
    if (paymentMethod) order.paymentMethod = paymentMethod;
    if (address) {
      // Nếu address là chuỗi JSON, parse nó
      if (typeof address === "string") {
        order.address = JSON.parse(address);
      } else {
        order.address = address;
      }
    }

    // Lưu lại thay đổi
    await order.save();

    res.status(200).json({
      success: true,
      message: "Cập nhật đơn hàng thành công",
      order,
    });
  } catch (error) {
    console.error("Error updating order:", error);
    res.status(500).json({
      success: false,
      message: "Lỗi khi cập nhật đơn hàng",
      error: error.message,
    });
  }
});

// Xóa đơn hàng
router.delete("/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Kiểm tra sự tồn tại của đơn hàng
    const order = await OrderModel.findById(id);
    if (!order) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy đơn hàng",
      });
    }

    // Thực hiện xóa
    await OrderModel.findByIdAndDelete(id);

    res.status(200).json({
      success: true,
      message: "Xóa đơn hàng thành công",
    });
  } catch (error) {
    console.error("Error deleting order:", error);
    res.status(500).json({
      success: false,
      message: "Lỗi khi xóa đơn hàng",
      error: error.message,
    });
  }
});

module.exports = router;

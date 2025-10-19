const express = require("express");
const router = express.Router();
const { SubCategoryModel } = require("../models/SubCategoryModel");
const { ProductModel } = require("../models/ProductModel");
const { checkAdminOrOwner, verifyToken } = require("../helper/authHelpers");

// Lấy tất cả SubCategory với phân trang
router.get("/", async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1; // Nếu không có page, mặc định là 1
    const perPage = 5; // Số lượng item mỗi trang

    if (req.query.page) {
      // Nếu có tham số page, thực hiện phân trang
      const totalPosts = await SubCategoryModel.countDocuments();
      const totalPages = Math.ceil(totalPosts / perPage);

      if (page > totalPages) {
        return res.status(404).json({
          success: false,
          message: "Page not found",
        });
      }

      // Sử dụng populate để lấy thông tin từ parentCategory
      const subcategoryList = await SubCategoryModel.find()
        .populate("parentCategory") // Lấy thông tin từ parentCategory
        .skip((page - 1) * perPage) // Bỏ qua các mục đã hiển thị trên các trang trước
        .limit(perPage) // Giới hạn số lượng mục trên mỗi trang
        .exec();

      if (!subcategoryList || subcategoryList.length === 0) {
        return res.status(404).json({
          success: true,
          message: "No subcategories found",
        });
      }

      return res.status(200).json({
        success: true,
        subcategories: subcategoryList,
        totalPages: totalPages,
        currentPage: page,
        totalItems: totalPosts,
        perPage: perPage,
      });
    } else {
      // Nếu không có tham số page, trả về tất cả danh mục
      const subcategoryList = await SubCategoryModel.find().populate(
        "parentCategory"
      );

      if (!subcategoryList || subcategoryList.length === 0) {
        return res.status(404).json({
          success: true,
          message: "No subcategories found",
        });
      }

      return res.status(200).json({
        success: true,
        subcategories: subcategoryList,
      });
    }
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: err.message || "An error occurred while fetching subcategories",
    });
  }
});

// Tìm Subcategory theo ID
router.get("/:id", async (req, res) => {
  try {
    // Lấy SubCategory theo ID và populate thông tin parentCategory
    const subcategory = await SubCategoryModel.findById(req.params.id).populate(
      "parentCategory"
    );

    // Kiểm tra nếu không tìm thấy subcategory
    if (!subcategory) {
      return res.status(404).json({
        success: false,
        message: "SubCategory not found",
        type: "error",
      });
    }

    return res.status(200).json({
      success: true,
      data: subcategory, // Trả về subcategory đã có thông tin của parentCategory
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message || "An error occurred while fetching the subcategory",
    });
  }
});

// Xóa subcategory
router.delete("/:id", verifyToken, checkAdminOrOwner, async (req, res) => {
  try {
    const subCategoryId = req.params.id;

    // Kiểm tra xem subcategory có tồn tại không
    const subCategory = await SubCategoryModel.findById(subCategoryId);
    if (!subCategory) {
      return res.status(404).json({
        message: "Danh mục con không được tìm thấy!",
        success: false,
        type: "error",
      });
    }

    // Kiểm tra số lượng sản phẩm đang sử dụng subcategory này
    const productCount = await ProductModel.countDocuments({
      sub_category: subCategoryId,
    });
    if (productCount > 0) {
      return res.status(400).json({
        success: false,
        message: `Không thể xóa danh mục con vì có ${productCount} sản phẩm đang sử dụng.`,
        type: "error",
      });
    }

    // Xóa subcategory khỏi cơ sở dữ liệu
    await SubCategoryModel.findByIdAndDelete(subCategoryId);

    return res.status(200).json({
      success: true,
      message: "Xóa danh mục con thành công!",
      type: "success",
    });
  } catch (err) {
    console.error("Error during subcategory deletion:", err);
    return res.status(500).json({
      message: err.message || "An error occurred",
      type: "error",
      success: false,
    });
  }
});

// Tạo subcategory
router.post("/create", verifyToken, checkAdminOrOwner, async (req, res) => {
  try {
    const { name, parentCategory } = req.body;

    // Kiểm tra dữ liệu
    if (!name) {
      return res.status(400).json({
        success: false,
        message: "Tên danh mục phụ là bắt buộc",
        type: "error",
      });
    }
    if (!parentCategory) {
      return res.status(400).json({
        success: false,
        message: "Danh mục cha là bắt buộc",
        type: "error",
      });
    }

    // Tạo subcategory mới
    const newSubCategory = new SubCategoryModel({
      name,
      parentCategory,
    });

    // Lưu vào database
    await newSubCategory.save();

    res.status(201).json({
      success: true,
      message: "Tạo thành công",
      type: "success",
      data: newSubCategory,
    });
  } catch (error) {
    console.error("API Error:", error); // Log lỗi để kiểm tra
    res.status(500).json({
      success: false,
      message: "Không thể tạo!",
      type: "error",
      error: error.message,
    });
  }
});

module.exports = router;

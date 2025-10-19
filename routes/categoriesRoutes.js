const { CategoryModel } = require("../models/CategoryModel");
const express = require("express");
const router = express.Router();
const pLimit = require("p-limit");
const cloudinary = require("../cloudinaryConfig");
const upload = require("../middlewares/multer");
const fs = require("fs");
const path = require("path");
const { SubCategoryModel } = require("../models/SubCategoryModel");
const { ProductModel } = require("../models/ProductModel");
const { verifyToken, checkAdminOrOwner } = require("../helper/authHelpers");

// Lấy tất cả Category với phân trang
router.get("/", async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1; // Nếu không có page, mặc định là 1
    const perPage = 5; // Số lượng item mỗi trang

    if (req.query.page) {
      // Nếu có tham số page, thực hiện phân trang
      const totalPosts = await CategoryModel.countDocuments();
      const totalPages = Math.ceil(totalPosts / perPage);

      if (page > totalPages) {
        return res.status(404).json({
          success: false,
          message: "Page not found",
        });
      }

      const categoryList = await CategoryModel.find()
        .skip((page - 1) * perPage) // Bỏ qua các mục đã hiển thị trên các trang trước
        .limit(perPage) // Giới hạn số lượng mục trên mỗi trang
        .exec();

      if (!categoryList || categoryList.length === 0) {
        return res.status(404).json({
          success: true,
          message: "No categories found",
        });
      }

      return res.status(200).json({
        success: true,
        categories: categoryList,
        totalPages: totalPages,
        currentPage: page,
        totalItems: totalPosts,
        perPage: perPage,
      });
    } else {
      // Nếu không có tham số page, trả về tất cả danh mục
      const categoryList = await CategoryModel.find();

      if (!categoryList || categoryList.length === 0) {
        return res.status(404).json({
          success: true,
          message: "No categories found",
        });
      }

      return res.status(200).json({
        success: true,
        categories: categoryList,
      });
    }
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message || "An error occurred while fetching categories",
    });
  }
});

// Tìm category theo ID
router.get("/:id", async (req, res) => {
  try {
    const category = await CategoryModel.findById(req.params.id);
    if (!category) {
      return res.status(404).json({
        success: false,
        message: "Category not found",
      });
    }

    // Trả về category tương ứng id
    return res.status(200).json({
      success: true,
      data: category,
    });
  } catch (err) {
    // Xử lý lỗi nếu có
    return res.status(500).json({
      success: false,
      error: err.message || "An error occurred while fetching the category",
    });
  }
});

// Xóa category
router.delete("/:id", verifyToken, checkAdminOrOwner, async (req, res) => {
  try {
    const categoryId = req.params.id;

    // Kiểm tra xem có subcategory nào đang chứa category này không
    const subcategory = await SubCategoryModel.findOne({
      parentCategory: categoryId,
    });
    if (subcategory) {
      return res.status(400).json({
        success: false,
        message: "Không thể xóa danh mục với các danh mục phụ hiện có.",
        type: "error",
      });
    }

    // Kiểm tra số lượng sản phẩm đang sử dụng category này
    const productCount = await ProductModel.countDocuments({
      category: categoryId,
    });
    if (productCount > 0) {
      return res.status(400).json({
        success: false,
        message: `Không thể xóa danh mục vì có ${productCount} sản phẩm đang sử dụng.`,
        type: "error",
      });
    }

    // Lấy thông tin category
    const category = await CategoryModel.findById(categoryId);
    if (!category) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy danh mục!",
        type: "error",
      });
    }

    // Xóa các ảnh liên quan trên Cloudinary
    await Promise.all(
      category.images.map(async (image) => {
        try {
          await cloudinary.uploader.destroy(image.public_id);
        } catch (error) {
          console.error(
            `Error deleting image with public_id ${image.public_id}:`,
            error
          );
        }
      })
    );

    // Xóa category khỏi cơ sở dữ liệu
    await CategoryModel.findByIdAndDelete(categoryId);

    return res.status(200).json({
      success: true,
      message: "Danh mục và hình ảnh liên quan đã được xóa thành công!",
      type: "success",
    });
  } catch (err) {
    console.error("Error during category deletion:", err);
    return res.status(500).json({
      error: false,
      message: err || "An error occurred",
      type: "error",
    });
  }
});

// Thêm mới category
router.post(
  "/create",
  upload.single("file"),
  verifyToken,
  checkAdminOrOwner,
  async (req, res) => {
    try {
      const { name, color, type } = req.body;

      // Kiểm tra các trường bắt buộc
      if (!name) {
        return res.status(400).json({
          success: false,
          message: "Tên danh mục là bắt buộc",
          type: "error",
        });
      }
      if (!color) {
        return res.status(400).json({
          success: false,
          message: "Nhập mã màu nền cho danh mục",
          type: "error",
        });
      }
      if (!type) {
        return res.status(400).json({
          success: false,
          message: "Nhập loại cho danh mục",
          type: "error",
        });
      }
      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: "Hình là bắt buộc",
          type: "error",
        });
      }

      // Giới hạn tải ảnh lên Cloudinary
      const limit = pLimit(1);
      const imageUpload = await limit(async () => {
        const result = await cloudinary.uploader.upload(req.file.path);

        // Xóa file tạm sau khi tải lên Cloudinary
        if (req.file && req.file.path) {
          fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting temporary file:", err);
          });
        }

        return {
          public_id: result.public_id,
          url: result.secure_url,
        };
      });

      // Tạo đối tượng Category mới
      const category = new CategoryModel({
        name,
        images: [imageUpload],
        color,
        type,
      });
      await category.save();

      res.status(201).json({
        success: true,
        message: "Tạo thành công!",
        type: "success",
        category,
      });
    } catch (error) {
      console.error("Error:", error);
      res.status(400).json({
        success: false,
        error: error, // Trả lỗi về cho frontend
      });
    }
  }
);

// Chỉnh sửa category theo ID
router.put(
  "/:id",
  upload.single("file"), // Đảm bảo rằng tên này khớp với tên trong FormData
  verifyToken,
  checkAdminOrOwner,
  async (req, res) => {
    try {
      const { name, color, type } = req.body; // Lấy thông tin từ req.body
      const categoryId = req.params.id;

      // Kiểm tra tính hợp lệ của ID
      if (!categoryId) {
        return res.status(400).json({
          success: false,
          message: "Category ID is required!",
          type: "error",
        });
      }

      const category = await CategoryModel.findById(categoryId);
      if (!category) {
        return res.status(404).json({
          success: false,
          message: "Category not found!",
          type: "error",
        });
      }
      if (!name) {
        return res.status(404).json({
          success: false,
          message: "Tên danh mục là bắt buộc",
          type: "error",
        });
      }
      if (!color) {
        return res.status(404).json({
          success: false,
          message: "Nhập mã màu nền cho danh mục",
          type: "error",
        });
      }
      if (!type) {
        return res.status(404).json({
          success: false,
          message: "Nhập loại cho danh mục",
          type: "error",
        });
      }

      // Xử lý tệp hình ảnh nếu có
      // Xử lý ảnh nếu có tệp mới được tải lên
      if (req.file) {
        // Xóa toàn bộ ảnh hiện có trên Cloudinary và cập nhật mảng images
        await Promise.all(
          category.images.map(async (image) => {
            try {
              await cloudinary.uploader.destroy(image.public_id);
            } catch (error) {
              console.error(
                `Error deleting image with public_id ${image.public_id}:`,
                error
              );
            }
          })
        );

        // Tải lên ảnh mới lên Cloudinary và cập nhật ảnh mới trong category
        const result = await cloudinary.uploader.upload(req.file.path);
        category.images = [
          { url: result.secure_url, public_id: result.public_id },
        ];
      }

      // Cập nhật tên và màu sắc của category
      category.name = name;
      category.color = color;
      category.type = type;

      // Lưu lại các thay đổi
      await category.save();

      return res.status(200).json({
        success: true,
        message: "Cập nhật thành công!",
        type: "success",
        category,
      });
    } catch (error) {
      console.error("Error:", error);
      res.status(400).json({
        success: false,
        error: error,
      });
    } finally {
      // Xóa file tạm sau khi tải lên Cloudinary (nếu có)
      if (req.file && req.file.path) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting temporary file:", err);
        });
      }
    }
  }
);

module.exports = router;

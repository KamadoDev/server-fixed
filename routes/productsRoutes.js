const { ProductModel } = require("../models/ProductModel");
const { CategoryModel } = require("../models/CategoryModel");
const { SubCategoryModel } = require("../models/SubCategoryModel");

const express = require("express");
const router = express.Router();
const validateObjectId = require("../middlewares/validateObjectId");
const pLimit = require("p-limit");
const cloudinary = require("../cloudinaryConfig");
const upload = require("../middlewares/multer");
const fs = require("fs");
const { verifyToken, checkAdminOrOwner } = require("../helper/authHelpers");
const { OrderModel } = require("../models/OrderModel");

// Lấy tất cả sản phẩm
router.get("/", async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1;
    const perPage = 12;

    // Kiểm tra nếu page không phải là số hợp lệ
    if (isNaN(page) || page < 1) {
      return res.status(400).json({
        success: false,
        message: "Invalid page number",
      });
    }

    const totalProducts = await ProductModel.countDocuments();
    const totalPages = Math.ceil(totalProducts / perPage);

    // Kiểm tra nếu page lớn hơn tổng số trang
    if (page > totalPages) {
      return res.status(404).json({
        success: false,
        message: "Page not found",
      });
    }

    // Truy vấn sản phẩm với phân trang
    const productList = await ProductModel.find()
      .populate(["category", "sub_category"])
      .skip((page - 1) * perPage)
      .limit(perPage)
      .exec();

    // Kiểm tra nếu không có sản phẩm
    if (productList.length === 0) {
      return res.status(200).json({
        success: true,
        message: "No products available",
      });
    }

    // Trả về thông tin sản phẩm và phân trang
    return res.status(200).json({
      success: true,
      products: productList,
      totalPages,
      currentPage: page,
      totalItems: totalProducts,
      perPage,
    });
  } catch (err) {
    // Xử lý lỗi nếu có
    console.error("Error fetching products:", err);
    return res.status(500).json({
      success: false,
      message: err.message || "An error occurred while fetching products",
    });
  }
});

// API thống kê tổng số lượng sản phẩm hiện có
router.get("/all-products", async (req, res) => {
  try {
    // Đếm tổng số sản phẩm trong cơ sở dữ liệu
    const totalProducts = await ProductModel.countDocuments();

    // Trả về kết quả
    return res.status(200).json({
      success: true,
      totalProducts, // Tổng số lượng sản phẩm
    });
  } catch (err) {
    console.error("Error fetching product count:", err);
    return res.status(500).json({
      success: false,
      message: "An error occurred while fetching product count.",
    });
  }
});

// API Get Product Seller với phân trang
router.get("/getProductSeller", async (req, res) => {
  try {
    const threshold = 2; // Ngưỡng tối thiểu để coi là bán chạy
    const page = parseInt(req.query.page, 10) || 1;
    const perPage = 10;

    // Aggregation pipeline để tính tổng số lượng bán của từng sản phẩm
    const salesData = await OrderModel.aggregate([
      { $match: { status: "Completed" } }, // Chỉ lấy đơn hàng đã hoàn thành
      { $unwind: "$items" }, // Tách từng phần tử trong mảng items
      {
        $group: {
          _id: "$items.productId", // Nhóm theo productId
          totalQuantity: { $sum: "$items.quantity" }, // Tính tổng số lượng bán
        },
      },
      { $match: { totalQuantity: { $gte: threshold } } }, // Chỉ lấy sản phẩm bán >= threshold
      { $sort: { totalQuantity: -1 } }, // Sắp xếp giảm dần theo số lượng
      { $skip: (page - 1) * perPage }, // Phân trang
      { $limit: perPage }, // Giới hạn số lượng sản phẩm trả về
    ]);

    // Lấy thông tin chi tiết của sản phẩm từ ProductModel
    const productIds = salesData.map((item) => item._id);
    const products = await ProductModel.find({ _id: { $in: productIds } })
      .populate(["category", "sub_category"])
      .exec();

    // Kết hợp thông tin sản phẩm với số lượng bán
    const result = salesData.map((sale) => {
      const product = products.find(
        (prod) => prod._id.toString() === sale._id.toString()
      );
      return {
        ...product.toObject(),
        totalSold: sale.totalQuantity, // Thêm tổng số lượng bán
      };
    });

    // Trả về kết quả
    return res.status(200).json({
      success: true,
      products: result,
      currentPage: page,
      perPage,
    });
  } catch (err) {
    console.error("Error fetching best-selling products:", err);
    return res.status(500).json({
      success: false,
      message: "An error occurred while fetching best-selling products.",
    });
  }
});

// sản phẩm nổi bật
router.get("/featured", async (req, res) => {
  try {
    const { idCat, perPage = 8, page = 1 } = req.query;

    // Tạo bộ lọc sản phẩm nổi bật
    const filter = { isFeatured: true };
    if (idCat) {
      const category = await CategoryModel.findById(idCat);
      if (!category) {
        return res.status(404).json({
          success: false,
          message: "Category not found",
        });
      }
      filter.category = category._id;
    }

    // Tính toán phân trang
    const limit = parseInt(perPage, 10) || 8;
    const skip = (parseInt(page, 10) - 1) * limit;

    // Truy vấn sản phẩm
    const productList = await ProductModel.find(filter).skip(skip).limit(limit);

    // Trả về thông tin sản phẩm
    return res.status(200).json({
      success: true,
      products: productList,
    });
  } catch (error) {
    console.error("Error fetching featured products:", error);
    return res.status(500).json({
      success: false,
      message:
        error.message || "An error occurred while fetching featured products",
    });
  }
});

// sản phẩm mới
router.get("/new", async (req, res) => {
  try {
    const { idCat, perPage = 12, page = 1 } = req.query;

    // Tạo bộ lọc sản phẩm
    const filter = {};
    if (idCat) {
      const category = await CategoryModel.findById(idCat);
      if (!category) {
        return res.status(404).json({
          success: false,
          message: "Category not found",
        });
      }
      filter.category = category._id;
    }

    // Tính toán phân trang
    const limit = parseInt(perPage, 10) || 12;
    const skip = (parseInt(page, 10) - 1) * limit;

    // Truy vấn sản phẩm mới
    const productList = await ProductModel.find(filter)
      .sort({ createdAt: -1 }) // Sắp xếp giảm dần theo ngày tạo
      .skip(skip)
      .limit(limit);

    return res.status(200).json({
      success: true,
      products: productList,
    });
  } catch (error) {
    console.error("Error fetching new products:", error);
    return res.status(500).json({
      success: false,
      message: error.message || "An error occurred while fetching new products",
    });
  }
});

// sản phẩm theo id categories và subcategory
router.get("/cat", async (req, res) => {
  try {
    const {
      id,
      perPage = 12,
      page = 1,
      minPrice,
      maxPrice,
      rating,
      status,
    } = req.query;

    // Kiểm tra id thuộc Category hoặc SubCategory
    let categoryId = null;
    let subCategoryId = null;

    const category = await CategoryModel.findById(id);
    if (category) {
      categoryId = category._id;
    } else {
      const subCategory = await SubCategoryModel.findById(id);
      if (subCategory) {
        subCategoryId = subCategory._id;
      }
    }

    if (!categoryId && !subCategoryId) {
      return res.status(404).json({
        success: false,
        message: "Category or SubCategory not found",
      });
    }

    // Tạo bộ lọc MongoDB
    const filter = {};

    if (categoryId) filter.category = categoryId;
    if (subCategoryId) filter.sub_category = subCategoryId;

    // Lọc theo giá nếu có
    if (!isNaN(minPrice) && !isNaN(maxPrice)) {
      filter.price = { $gte: parseInt(minPrice), $lte: parseInt(maxPrice) };
    } else if (!isNaN(minPrice)) {
      filter.price = { $gte: parseInt(minPrice) };
    } else if (!isNaN(maxPrice)) {
      filter.price = { $lte: parseInt(maxPrice) };
    }

    // Lọc theo đánh giá nếu có
    if (!isNaN(rating)) {
      filter.rating = { $gte: parseFloat(rating) };
    }

    // Lọc theo trạng thái nếu có (kiểm tra sản phẩm còn hàng)
    if (status === "in-stock") {
      filter.productInStock = { $gt: 0 }; // Chỉ lấy sản phẩm còn hàng (số lượng > 0)
    } else if (status === "out-of-stock") {
      filter.productInStock = { $lte: 0 }; // Chỉ lấy sản phẩm hết hàng (số lượng <= 0)
    }

    // Tính toán phân trang
    const limit = Math.max(parseInt(perPage, 10), 1); // Đảm bảo `perPage >= 1`
    const skip = Math.max((parseInt(page, 10) - 1) * limit, 0); // Đảm bảo `skip >= 0`

    // Lấy danh sách sản phẩm
    const productList = await ProductModel.find(filter)
      .sort({ createdAt: -1 }) // Sắp xếp theo thời gian tạo
      .skip(skip)
      .limit(limit);

    // Tính tổng số sản phẩm
    const totalProducts = await ProductModel.countDocuments(filter);
    const totalPages = Math.ceil(totalProducts / limit);

    return res.status(200).json({
      success: true,
      products: productList,
      pagination: {
        totalProducts,
        perPage: limit,
        currentPage: parseInt(page, 10),
        totalPages,
      },
    });
  } catch (error) {
    console.error("Error fetching products by category or subcategory:", error);
    return res.status(500).json({
      success: false,
      message: error.message || "An error occurred while fetching products",
    });
  }
});

// sản phẩm liên quan
router.get("/related", async (req, res) => {
  try {
    const {
      tag, // Tag của sản phẩm hiện tại
      catID, // ID của category hoặc subcategory
      perPage = 12, // Số sản phẩm trên mỗi trang (mặc định 12)
      page = 1, // Trang hiện tại (mặc định 1)
    } = req.query;

    // Kiểm tra tính hợp lệ của category/subcategory ID
    let categoryId = null;
    let subCategoryId = null;

    const category = await CategoryModel.findById(catID);
    if (category) {
      categoryId = category._id;
    } else {
      const subCategory = await SubCategoryModel.findById(catID);
      if (subCategory) {
        subCategoryId = subCategory._id;
      }
    }

    if (!categoryId && !subCategoryId) {
      return res.status(404).json({
        success: false,
        message: "Category or SubCategory not found",
      });
    }

    // Tạo bộ lọc MongoDB
    const filter = {};

    if (categoryId) filter.category = categoryId;
    if (subCategoryId) filter.sub_category = subCategoryId;

    // Lọc theo tag nếu có
    if (tag) {
      filter.tags = { $in: [tag] }; // Kiểm tra nếu tag nằm trong danh sách tags của sản phẩm
    }

    // Phân trang
    const limit = Math.max(parseInt(perPage, 10), 1); // Đảm bảo `perPage >= 1`
    const skip = Math.max((parseInt(page, 10) - 1) * limit, 0); // Đảm bảo `skip >= 0`

    // Lấy danh sách sản phẩm
    const relatedProducts = await ProductModel.find(filter)
      .sort({ createdAt: -1 }) // Sắp xếp theo thời gian tạo
      .skip(skip)
      .limit(limit);

    // Tính tổng số sản phẩm liên quan
    const totalRelatedProducts = await ProductModel.countDocuments(filter);
    const totalPages = Math.ceil(totalRelatedProducts / limit);

    return res.status(200).json({
      success: true,
      products: relatedProducts,
      pagination: {
        totalProducts: totalRelatedProducts,
        perPage: limit,
        currentPage: parseInt(page, 10),
        totalPages,
      },
    });
  } catch (error) {
    console.error("Error fetching related products:", error);
    return res.status(500).json({
      success: false,
      message:
        error.message || "An error occurred while fetching related products",
    });
  }
});

// Tìm sản phẩm theo ID
router.get("/:id", async (req, res) => {
  try {
    const product = await ProductModel.findById(req.params.id).populate([
      "category",
      "sub_category",
    ]);
    if (!product) {
      return res.status(404).json({
        success: false,
        message: "Product not found",
      });
    }

    // Trả về sản phẩm tương ứng id
    return res.status(200).json({
      success: true,
      product,
    });
  } catch (err) {
    // Xử lý lỗi nếu có
    return res.status(500).json({
      success: false,
      error: err.message || "An error occurred while fetching the product",
    });
  }
});

// Xóa sản phẩm
router.delete("/:id", verifyToken, checkAdminOrOwner, async (req, res) => {
  try {
    const productId = req.params.id;
    const product = await ProductModel.findById(productId);
    if (!product) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy sản phẩm!",
        type: "error",
      });
    }

    // Xóa các ảnh liên quan trên Cloudinary
    await Promise.all(
      product.images.map(async (image) => {
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
    await ProductModel.findByIdAndDelete(productId);

    return res.status(200).json({
      success: true,
      message: "Sản phẩm và hình ảnh liên quan đã được xóa thành công!",
      type: "success",
    });
  } catch (err) {
    console.error("Error during Product deletion:", err);
    return res.status(500).json({
      success: false,
      message: err || "An error occurred",
      type: "error",
    });
  }
});

// xóa ảnh
router.post("/upload/remove", async (req, res) => {
  const { public_id, productID_ } = req.body;

  // Kiểm tra public_id và productID có được cung cấp không
  if (!public_id || !productID_) {
    return res.status(400).json({
      success: false,
      message: "Image ID and Product ID are required",
      type: "error",
    });
  }

  try {
    // Xóa ảnh từ Cloudinary
    const result = await cloudinary.uploader.destroy(public_id);

    // Kiểm tra kết quả xóa ảnh
    if (result.result !== "ok") {
      return res.status(400).json({
        success: false,
        message: "Failed to delete image",
        type: "error",
      });
    }

    // Cập nhật lại danh sách ảnh của sản phẩm trong cơ sở dữ liệu
    const product = await ProductModel.findById(productID_);

    if (!product) {
      return res.status(404).json({
        success: false,
        message: "Product not found",
        type: "error",
      });
    }

    // Lọc bỏ ảnh đã xóa khỏi danh sách images của sản phẩm
    product.images = product.images.filter(
      (image) => image.public_id !== public_id
    );

    // Lưu lại sản phẩm với danh sách ảnh đã được cập nhật
    await product.save();

    return res.status(200).json({
      success: true,
      message: "Image deleted and product updated successfully",
    });
  } catch (error) {
    console.error("Error deleting image from Cloudinary:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete image and update product",
      error: error.message,
    });
  }
});

// tải lên nhiều ảnh
router.post("/upload", upload.array("images"), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        success: false,
        message: "No images uploaded",
        type: "error",
      });
    }

    const uploadPromises = req.files.map(async (file) => {
      try {
        const result = await cloudinary.uploader.upload(file.path);
        // Xóa file tạm sau khi tải lên Cloudinary
        await fs.promises.unlink(file.path);
        return { url: result.secure_url, public_id: result.public_id };
      } catch (error) {
        console.error("Error uploading image to Cloudinary:", error);
        throw new Error("Failed to upload image to Cloudinary");
      }
    });

    const uploadedImages = await Promise.all(uploadPromises);

    return res.status(200).json({
      success: true,
      message: "Images uploaded successfully",
      images: uploadedImages,
    });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to upload images",
      error: error.message,
    });
  }
});

// Tạo sản phẩm mới
router.post(
  "/create",
  upload.array("images", 5),
  verifyToken,
  checkAdminOrOwner,
  async (req, res) => {
    try {
      // Kiểm tra các tệp đã được tải lên
      if (!req.files || req.files.length === 0) {
        return res.status(400).json({
          success: false,
          message: "Bạn phải tải lên ít nhất 1 ảnh!",
          type: "error",
        });
      }

      // Kiểm tra lại các tệp nếu có
      for (const file of req.files) {
        const fileExtension = file.originalname.split(".").pop().toLowerCase();
        if (!["jpeg", "jpg", "png", "gif"].includes(fileExtension)) {
          return res.status(400).json({
            success: false,
            message: `Ảnh ${file.originalname} không hợp lệ. Chỉ chấp nhận JPEG, JPG, PNG, GIF!`,
            type: "error",
          });
        }
      }
      // Bẫy lỗi các trường bắt buộc
      const {
        name,
        description,
        price,
        old_price,
        discount,
        brand,
        productInStock,
        isFeatured,
        size,
        colors,
        tags,
        rating,
        category: idCat,
        sub_category: idSubCat,
      } = req.body;

      // Kiểm tra các trường bắt buộc
      const requiredFields = [
        { field: name, message: "Tên sản phẩm không được để trống" },
        { field: description, message: "Mô tả sản phẩm không được để trống" },
        {
          field: price,
          message: "Giá sản phẩm không được để trống",
          type: "number",
          min: 0,
        },
        {
          field: old_price,
          message: "Giá củ sản phẩm không được để trống",
          type: "number",
          min: 0,
        },
        {
          field: discount,
          message: "Giảm giá sản phẩm không được để trống",
          type: "number",
          min: 0,
          max: 100,
        },
        { field: brand, message: "Thương hiệu sản phẩm không được để trống" },
        { field: size, message: "Kích thước sản phẩm không được để trống" },
        { field: colors, message: "Màu sản phẩm không được để trống" },
        {
          field: productInStock,
          message: "Số lượng sản phẩm trong kho không được để trống",
          type: "number",
          min: 0,
        },
        {
          field: isFeatured,
          message: "Tùy chọn ưu tiên sản phẩm không được để trống",
        },
        { field: tags, message: "Ít nhất có 2 tags sản phẩm", type: "array" },
        { field: idCat, message: "Danh mục sản phẩm không được để trống" },
        {
          field: idSubCat,
          message: "Danh mục phụ sản phẩm không được để trống",
        },
        {
          field: rating,
          message: "Đánh giá sản phẩm không được để trống",
        },
      ];

      for (const { field, message, type, min, max } of requiredFields) {
        if (!field && field !== 0) {
          return res
            .status(400)
            .json({ success: false, message, type: "error" });
        }
        if (
          type === "number" &&
          (isNaN(field) ||
            (min !== undefined && field < min) ||
            (max !== undefined && field > max))
        ) {
          return res.status(400).json({
            success: false,
            message: `${message} và phải là số thực từ ${min}`,
            type: "error",
          });
        }
        if (type === "array" && !Array.isArray(field)) {
          return res
            .status(400)
            .json({ success: false, message, type: "error" });
        }
      }

      // Kiểm tra danh mục
      const category = await CategoryModel.findById(idCat);
      if (!category) {
        return res.status(400).json({
          success: false,
          message: "Danh mục không tồn tại",
          type: "error",
        });
      }

      const subCategory = await SubCategoryModel.findById(idSubCat);
      if (!subCategory) {
        // Kiểm tra nếu sub_category là con của category
        return res.status(400).json({
          success: false,
          message: "Danh mục phụ không hợp lệ",
          type: "error",
        });
      }

      // Kiểm tra số lượng ảnh
      if (req.files && req.files.length > 5) {
        return res.status(400).json({
          success: false,
          message: "Chỉ có thể tải lên tối đa 5 ảnh!",
          type: "error",
        });
      }

      // Xử lý ảnh
      let images = [];
      if (req.files) {
        const imageUploadPromises = req.files.map(async (file) => {
          try {
            const result = await cloudinary.uploader.upload(file.path);
            return { url: result.secure_url, public_id: result.public_id };
          } catch (uploadError) {
            console.error("Lỗi khi tải ảnh lên:", uploadError);
            throw new Error("Lỗi tải ảnh");
          }
        });
        images = await Promise.all(imageUploadPromises);
      }

      // Tạo sản phẩm mới
      const newProduct = new ProductModel({
        name,
        description,
        price,
        old_price,
        discount,
        brand,
        productInStock,
        isFeatured,
        size,
        colors,
        tags,
        images,
        category: idCat,
        sub_category: idSubCat,
        rating,
      });

      const createdProduct = await newProduct.save();

      return res.status(201).json({
        success: true,
        message: "Tạo thành công!",
        type: "success",
        product: createdProduct,
      });
    } catch (error) {
      console.error("Lỗi:", error);
      res.status(500).json({
        success: false,
        error: error.message,
      });
    } finally {
      // Xóa file tạm sau khi tải lên Cloudinary
      if (req.files && req.files.length > 0) {
        await Promise.all(
          req.files.map(async (file) => {
            try {
              await fs.promises.unlink(file.path);
            } catch (err) {
              console.error("Lỗi khi xóa file tạm:", err);
            }
          })
        );
      }
    }
  }
);

// Cập nhật sản phẩm
router.put(
  "/:id",
  upload.array("files", 5),
  verifyToken,
  checkAdminOrOwner,
  async (req, res) => {
    try {
      const { id } = req.params;
      const {
        category: idCat,
        sub_category: idSubCat,
        name,
        description,
        price,
        old_price,
        discount,
        brand,
        productInStock,
        isFeatured,
        size,
        colors,
        tags,
        numberReviews,
        rating,
        public_id, // Nhận public_id từ request body để xóa ảnh
      } = req.body;

      // Validate the product ID
      if (!id) {
        return res.status(400).json({
          success: false,
          message: "ID sản phẩm không hợp lệ",
          type: "error",
        });
      }

      // Find the product
      const product = await ProductModel.findById(id);
      if (!product) {
        return res.status(404).json({
          success: false,
          message: "Không tìm thấy sản phẩm",
          type: "error",
        });
      }

      // Xóa ảnh cũ nếu có public_id trong request body
      if (public_id) {
        // Tìm ảnh cần xóa trong mảng product.images
        const imageToDelete = product.images.find(
          (image) => image.public_id === public_id
        );

        if (imageToDelete) {
          try {
            // Xóa ảnh từ Cloudinary
            const result = await cloudinary.uploader.destroy(public_id);
            if (result.result !== "ok") {
              return res.status(400).json({
                success: false,
                message: "Không thể xóa hình ảnh",
                type: "error",
              });
            }

            // Cập nhật lại mảng images trong sản phẩm (xóa ảnh đã xóa)
            product.images = product.images.filter(
              (image) => image.public_id !== public_id
            );
          } catch (error) {
            console.error("Error deleting image:", error);
            return res.status(500).json({
              success: false,
              message: "Error deleting image",
              type: "error",
            });
          }
        }
      }

      // Validate category and subcategory
      const category = await CategoryModel.findById(idCat);
      if (!category) {
        return res.status(400).json({
          success: false,
          message: "Danh mục không tồn tại",
          type: "error",
        });
      }

      const subCategory = await SubCategoryModel.findById(idSubCat);
      if (!subCategory) {
        return res.status(400).json({
          success: false,
          message: "Danh mục phụ không tồn tại",
          type: "error",
        });
      }

      // Validate required fields
      if (
        !name ||
        !description ||
        !price ||
        !brand ||
        !productInStock ||
        !size ||
        !colors
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Tên, mô tả, giá cả, nhãn hiệu, số lượng kho, kích thước và màu sản phẩm là bắt buộc!",
          type: "error",
        });
      }

      // Validate image count (max 5)
      if (req.files && req.files.length > 5) {
        return res.status(400).json({
          success: false,
          message: "Bạn chỉ có thể tải lên tối đa 5 hình ảnh!",
          type: "error",
        });
      }

      // Process images if provided
      if (req.files && req.files.length > 0) {
        const imageUploadPromises = req.files.map(async (file) => {
          try {
            const result = await cloudinary.uploader.upload(file.path);
            return { url: result.secure_url, public_id: result.public_id };
          } catch (uploadError) {
            console.error("Error uploading image:", uploadError);
            throw new Error("Failed to upload image");
          }
        });

        // Cập nhật mảng images của sản phẩm với ảnh mới
        product.images = [
          ...product.images,
          ...(await Promise.all(imageUploadPromises)),
        ];
      }

      // Cập nhật các trường dữ liệu khác cho sản phẩm
      product.name = name;
      product.description = description;
      product.price = price;
      product.old_price = old_price;
      product.discount = discount;
      product.brand = brand;
      product.productInStock = productInStock;
      product.isFeatured = isFeatured;
      product.size = size;
      product.colors = colors;
      product.tags = tags;
      product.numberReviews = numberReviews;
      product.rating = rating;
      product.category = idCat;
      product.sub_category = idSubCat;

      // Save the updated product
      const updatedProduct = await product.save();

      return res.status(200).json({
        success: true,
        message: "Cập nhật thành công!",
        type: "success",
        product: updatedProduct,
      });
    } catch (error) {
      console.error("Error:", error);
      return res.status(500).json({
        success: false,
        message: error.message,
        type: "error",
      });
    } finally {
      // Dọn dẹp các tệp tạm thời sau khi tải ảnh lên
      if (req.files && req.files.length > 0) {
        await Promise.all(
          req.files.map(async (file) => {
            try {
              await fs.promises.unlink(file.path);
            } catch (err) {
              console.error("Error deleting temporary file:", err);
            }
          })
        );
      }
    }
  }
);

module.exports = router;

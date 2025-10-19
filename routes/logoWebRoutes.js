const { LogoWebModel } = require("../models/LogoWebModel");
const express = require("express");
const router = express.Router();
const cloudinary = require("../cloudinaryConfig");
const upload = require("../middlewares/multer");
const fs = require("fs");

// Lấy LogoWeb hiện tại
router.get("/", async (req, res) => {
  try {
    const logo = await LogoWebModel.findOne();
    if (!logo) {
      return res.status(404).json({
        success: false,
        message: "Logo not found",
      });
    }
    res.status(200).json({
      success: true,
      data: logo,
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message || "An error occurred while fetching the logo",
    });
  }
});

// Ghi đè LogoWeb mới
router.put(
  "/",
  upload.single("file"),
  async (req, res) => {
    try {
      const { type } = req.body;

      let logo = await LogoWebModel.findOne();
      if (!logo) {
        logo = new LogoWebModel();
      }

      if (type) logo.type = type;

      if (req.file) {
        // Xóa ảnh cũ trên Cloudinary nếu có
        if (logo.images && logo.images.length > 0) {
          await Promise.all(
            logo.images.map(async (image) => {
              await cloudinary.uploader.destroy(image.public_id);
            })
          );
        }

        // Tải ảnh mới lên Cloudinary
        const result = await cloudinary.uploader.upload(req.file.path);

        // Xóa file tạm sau khi tải lên Cloudinary
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting temporary file:", err);
        });

        logo.images = [
          {
            url: result.secure_url,
            public_id: result.public_id,
          },
        ];
      }

      await logo.save();
      res.status(200).json({
        success: true,
        message: "Logo updated successfully",
        data: logo,
      });
    } catch (err) {
      res.status(500).json({
        success: false,
        error: err.message || "An error occurred while updating the logo",
      });
    }
  }
);

module.exports = router;

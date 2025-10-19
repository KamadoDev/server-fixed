const mongoose = require("mongoose");

const SlideBannerSchema = new mongoose.Schema(
  {
    images: [
      {
        url: { type: String, required: true },
        public_id: { type: String, required: true },
      },
    ],
    position: {
      type: Number, // Add position to control the order of slides
      required: true,
      unique: true, // Ensure unique positions
    },
  },
  { timestamps: true }
);

// Create virtual for the id property
SlideBannerSchema.virtual("id").get(function () {
  return this._id.toHexString();
});

// Configure JSON output to include virtual properties
SlideBannerSchema.set("toJSON", {
  virtuals: true,
});

// Create and export the SlideBanner model
module.exports = {
  SlideBannerModel: mongoose.model("SlideBanner", SlideBannerSchema),
  SlideBannerSchema: SlideBannerSchema,
};

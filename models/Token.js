const mongoose = require("mongoose");
const { tokenTypes } = require("../config/Tokens");

const tokenSchema = new mongoose.Schema({
  _userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: "User",
  },
  token: { type: String, required: true },
  type: {
    type: String,
    enum: [
      tokenTypes.ACCESS,
      tokenTypes.REFRESH,
      tokenTypes.RESET_PASSWORD,
      tokenTypes.VERIFY_EMAIL,
    ],
    required: true,
  },
  expireAt: { type: Date, default: Date.now, index: { expires: 86400000 } },
});

module.exports = mongoose.model("Token", tokenSchema);

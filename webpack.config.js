const path = require("path");

module.exports = {
  entry: "./static/upload.js",
  output: {
    path: path.resolve(__dirname, "static/dist"),
    filename: "bundle.js",
  },
  mode: "production",
};

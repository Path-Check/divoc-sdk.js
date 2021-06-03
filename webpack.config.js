const path = require('path');

module.exports = {
  mode: "production",
  entry: "./lib/main.js",
  devtool: "source-map",
  output: {
    filename: 'divoc-sdk.min.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'DIVOC',
    libraryTarget: 'umd',
  },
  optimization: {
    minimize: true
  }
};
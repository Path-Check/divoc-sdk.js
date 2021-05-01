const path = require('path');

module.exports = {
  mode: "production",
  entry: "./lib/index.js",
  devtool: "source-map",
  output: {
    filename: 'divoc.min.js',
    path: path.resolve(__dirname, 'dist'),
    library: 'DIVOC',
    libraryTarget: 'umd',
  },
  optimization: {
    minimize: false
  }
};
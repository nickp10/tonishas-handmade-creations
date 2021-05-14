const CopyWebpackPlugin = require("copy-webpack-plugin");
const path = require("path");
const webpack = require("webpack");

const APP_DIR = path.resolve(__dirname, "./src/client");
const BUILD_DIR = path.resolve(__dirname, "./build");

module.exports = {
    entry: {
        main: path.join(APP_DIR, "index.tsx")
    },
    output: {
        filename: "client.js",
        path: BUILD_DIR,
        publicPath: "/"
    },
    module: {
        rules: [
            {
                test: /\.(css)$/,
                use: [
                    {
                        loader: "style-loader",
                        options: {
                            esModule: false
                        }
                    },
                    {
                        loader: "css-loader",
                        options: {
                            modules: true
                        }
                    }
                ]
            },
            {
                test: /\.(ts|tsx)$/,
                loader: "ts-loader"
            },
            {
                test: /\.(js|jsx)$/,
                use: [
                    {
                        loader: "babel-loader",
                        options: {
                            cacheDirectory: true,
                            presets: ["@babel/preset-react", "@babel/preset-env"]
                        }
                    }
                ]
            },
            {
                test: /\.(woff|woff2|eot|ttf|otf)$/,
                use: [
                    {
                        loader: 'file-loader'
                    }
                ]
            }
        ]
    },
    resolve: {
        extensions: [".js", ".jsx", ".json", ".ts", ".tsx", ".css"]
    },
    plugins: [
        new CopyWebpackPlugin({
            patterns: [
                {
                    from: path.join(APP_DIR, "images"),
                    to: path.join(BUILD_DIR, "images")
                }
            ]
        })
    ]
};

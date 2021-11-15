const gulp = require("gulp");
const browserify = require("browserify");
const source = require("vinyl-source-stream");
const tsify = require("tsify");
const fancy_log = require("fancy-log");
const uglify = require("gulp-uglify");
const sourcemaps = require("gulp-sourcemaps");
const buffer = require("vinyl-buffer");
const gulpif = require("gulp-if");

const config = {
  sourceMaps: process.env.NODE_ENV !== "production",
  background: "./src/background.ts",
  intercept: "./src/intercept.ts",
  backgroundOutputFilename: "background.js",
  interceptOutputFilename: "intercept.js",
  outDir: "build",
  paths: {
    manifest: "src/manifest.json",
    background: ["src/**/*.ts", "!src/intercept.ts"],
    intercept: "src/intercept.ts",
  },
};

const createBrowserify = (entry, filename) => {
  return browserify({
    debug: config.sourceMaps,
    entries: [entry],
  })
    .plugin(tsify)
    .bundle()
    .on("error", fancy_log)
    .pipe(source(filename))
    .pipe(buffer())
    .pipe(gulpif(config.sourceMaps, sourcemaps.init({ loadMaps: true })))
    .pipe(uglify({ mangle: false, compress: false }))
    .pipe(gulpif(config.sourceMaps, sourcemaps.write()))
    .pipe(gulp.dest(config.outDir));
};

const background = () => {
  return createBrowserify(config.background, config.backgroundOutputFilename);
};

const intercept = () => {
  return createBrowserify(config.intercept, config.interceptOutputFilename);
};

const manifest = () => {
  return gulp.src(config.paths.manifest).pipe(gulp.dest(config.outDir));
};

const watch = () => {
  gulp.watch(config.paths.manifest, manifest);
  gulp.watch(config.paths.background, background);
  gulp.watch(config.paths.intercept, intercept);
};

exports.build = gulp.parallel(manifest, background, intercept);
exports.dev = gulp.parallel(manifest, background, intercept, watch);

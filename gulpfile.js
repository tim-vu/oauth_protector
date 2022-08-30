const gulp = require("gulp");
const browserify = require("browserify");
const source = require("vinyl-source-stream");
const tsify = require("tsify");
const fancy_log = require("fancy-log");
const uglify = require("gulp-uglify");
const sourcemaps = require("gulp-sourcemaps");
const buffer = require("vinyl-buffer");
const gulpif = require("gulp-if");
const babelify = require("babelify");

const config = {
  sourceMaps: process.env.NODE_ENV !== "production",
  entries: {
    background: {
      entryPoint: "./src/background.ts",
      outputFilename: "background.js",
      paths: ["src/**/*.ts", "!src/injector.ts", "!src/interceptor.js"],
      ts: true,
    },
    injector: {
      entryPoint: "./src/injector.ts",
      outputFilename: "injector.js",
      paths: "src/injector.ts",
      ts: true,
    },
    interceptor: {
      entryPoint: "src/interceptor.js",
      outputFilename: "interceptor.js",
      paths: "src/interceptor.js",
      ts: false,
    },
  },
  out: "build",
  paths: ["src/manifest.json", "src/img/*"],
};

const createTypescriptTask = (entry, output) => {
  return browserify({
    debug: config.sourceMaps,
    entries: [entry],
    basedir: ".",
  })
    .plugin(tsify, { global: true })
    .transform(
      babelify.configure({
        presets: ["@babel/preset-env"],
      })
    )
    .bundle()
    .on("error", fancy_log)
    .pipe(source(output))
    .pipe(buffer())
    .pipe(gulpif(config.sourceMaps, sourcemaps.init({ loadMaps: true })))
    .pipe(uglify({ mangle: false, compress: false }))
    .pipe(gulpif(config.sourceMaps, sourcemaps.write()))
    .pipe(gulp.dest(config.out));
};

const createJavascriptTask = (entry, output) => {
  return browserify({
    debug: config.sourceMaps,
    entries: [entry],
  })
    .transform(
      babelify.configure({
        presets: ["@babel/preset-env"],
      })
    )
    .bundle()
    .on("error", fancy_log)
    .pipe(source(output))
    .pipe(buffer())
    .pipe(gulpif(config.sourceMaps, sourcemaps.init({ loadMaps: true })))
    .pipe(uglify({ mangle: false, compress: false }))
    .pipe(gulpif(config.sourceMaps, sourcemaps.write()))
    .pipe(gulp.dest(config.out));
};

const compileTasksMap = Object.keys(config.entries).reduce((prev, key) => {
  prev[key] = () => {
    const entryPoint = config.entries[key].entryPoint;
    const output = config.entries[key].outputFilename;
    return config.entries[key].ts
      ? createTypescriptTask(entryPoint, output)
      : createJavascriptTask(entryPoint, output);
  };
  return prev;
}, {});

const compileTasks = Object.values(compileTasksMap);

const assets = () => {
  return gulp.src(config.paths, { base: "src" }).pipe(gulp.dest(config.out));
};

const watch = () => {
  gulp.watch(config.paths, assets);

  for (const key in config.entries) {
    gulp.watch(config.entries[key].paths, compileTasksMap[key]);
  }
};

exports.build = gulp.parallel(assets, ...compileTasks);
exports.dev = gulp.parallel(assets, ...compileTasks, watch);

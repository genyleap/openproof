// C++ lexical prefilter for source-level coroutine migration auditing.
// Preserve exact offsets and line breaks so findings still point at the
// correct original source line. This is not a C++ parser or runtime proof.
const blank = (s) => s.replace(/[^\n]/g, " ");
const digit = (c) => c !== undefined && /[0-9]/.test(c);

export function cppExecutableText(source) {
  let result = "";
  let i = 0;
  while (i < source.length) {
    const start = i;
    const current = source[i];
    const next = source[i + 1];
    if (current === "/" && next === "/") {
      const end = source.indexOf("\n", i + 2);
      i = end < 0 ? source.length : end;
      result += blank(source.slice(start, i));
      continue;
    }
    if (current === "/" && next === "*") {
      const end = source.indexOf("*/", i + 2);
      i = end < 0 ? source.length : end + 2;
      result += blank(source.slice(start, i));
      continue;
    }
    if (current === "R" && next === '"' &&
        (i === 0 || !/[A-Za-z_0-9]/.test(source[i - 1]))) {
      const open = source.indexOf("(", i + 2);
      if (open > 0 && open - (i + 2) <= 16) {
        const delimiter = source.slice(i + 2, open);
        if (!/[()\\\s]/.test(delimiter)) {
          const close = source.indexOf(")" + delimiter + '"', open + 1);
          i = close < 0 ? source.length : close + delimiter.length + 2;
          result += blank(source.slice(start, i));
          continue;
        }
      }
    }
    // C++ numeric separators use apostrophes and are not character literals.
    if (current === "'" && digit(source[i - 1]) && digit(next)) {
      result += current;
      ++i;
      continue;
    }
    if (current === '"' || current === "'") {
      const delimiter = current;
      ++i;
      while (i < source.length) {
        if (source[i] === "\\") {
          i = Math.min(source.length, i + 2);
          continue;
        }
        if (source[i] === delimiter) {
          ++i;
          break;
        }
        ++i;
      }
      result += blank(source.slice(start, i));
      continue;
    }
    result += current;
    ++i;
  }
  if (result.length !== source.length) {
    throw new Error("C++ lexical audit corrupted source offsets");
  }
  return result;
}

// EAF-owned ESLint flat config. The assessed repository's own ESLint configuration is
// never loaded (it is executable JavaScript). Only core ESLint rules are used so that
// results do not depend on plugins installed in the repository.
// EAF_ESLINT_LANG=js|ts selects which file family is linted.
"use strict";

const lang = process.env.EAF_ESLINT_LANG || "js";

const coreRules = {
  // security relevant
  "no-eval": "error",
  "no-implied-eval": "error",
  "no-new-func": "error",
  "no-script-url": "error",
  // probable bugs
  "no-cond-assign": "error",
  "no-constant-condition": "error",
  "no-debugger": "error",
  "no-dupe-args": "error",
  "no-dupe-keys": "error",
  "no-dupe-else-if": "error",
  "no-duplicate-case": "error",
  "no-fallthrough": "error",
  "no-func-assign": "error",
  "no-self-assign": "error",
  "no-self-compare": "error",
  "no-sparse-arrays": "error",
  "no-unreachable": "error",
  "no-unsafe-finally": "error",
  "no-unsafe-negation": "error",
  "no-prototype-builtins": "error",
  "no-loss-of-precision": "error",
  "use-isnan": "error",
  "valid-typeof": "error",
  "no-with": "error",
  // maintainability (warnings)
  "eqeqeq": "warn",
  "no-empty": "warn",
  "no-var": "warn",
  "complexity": ["warn", 15],
};

const linterOptions = { reportUnusedDisableDirectives: "off" };
const configs = [];

if (lang === "js") {
  configs.push({
    files: ["**/*.js", "**/*.mjs", "**/*.jsx"],
    linterOptions,
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    rules: { ...coreRules, "no-unused-vars": "warn", "no-redeclare": "error" },
  });
  configs.push({
    files: ["**/*.cjs"],
    linterOptions,
    languageOptions: { ecmaVersion: "latest", sourceType: "commonjs" },
    rules: { ...coreRules, "no-unused-vars": "warn", "no-redeclare": "error" },
  });
} else {
  // Resolved through NODE_PATH; the adapter reports NOT_EXECUTED if it is missing.
  const tsParser = require("@typescript-eslint/parser");
  configs.push({
    files: ["**/*.ts", "**/*.tsx", "**/*.mts", "**/*.cts"],
    linterOptions,
    languageOptions: {
      parser: tsParser,
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    // no-unused-vars / no-redeclare are unreliable on TypeScript without the TS plugin.
    rules: coreRules,
  });
}

module.exports = configs;

import js from "@eslint/js";
import globals from "globals";
import react from "eslint-plugin-react";

const unusedVars = [
  "error",
  {
    argsIgnorePattern: "^_",
    caughtErrors: "none",
    varsIgnorePattern: "^(React|_)",
  },
];

export default [
  {
    ignores: [
      "**/node_modules/**",
      "**/dist/**",
      "**/build/**",
      "**/coverage/**",
      "mobile/android/**",
    ],
  },
  {
    files: ["frontend/src/**/*.{js,jsx}"],
    ...js.configs.recommended,
    plugins: { react },
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
    rules: {
      ...js.configs.recommended.rules,
      "no-unused-vars": unusedVars,
      "react/jsx-uses-vars": "error",
    },
  },
  {
    files: ["desktop/**/*.js"],
    ...js.configs.recommended,
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "commonjs",
      globals: {
        ...globals.node,
      },
    },
    rules: {
      ...js.configs.recommended.rules,
      "no-unused-vars": unusedVars,
    },
  },
];

/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          900: "#0b0f19",
          850: "#0f172a",
          800: "#131d38",
          700: "#1e293b",
          600: "#334155",
          accent: "#0284c7",
          neon: "#38bdf8",
        }
      }
    },
  },
  plugins: [],
}


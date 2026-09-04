module.exports = {
  content: [
    "./templates/**/*.html",
    "./modules/**/*.html",
    "./static/js/**/*.js",
  ],
  safelist: ["hidden", "block", "flex", "overflow-hidden", "rotate-180", "opacity-40"],
  theme: {
    extend: {
      colors: {
        primary: "#0f3d8a",
        "primary-dark": "#092b63",
        sidebar: "#07152e",
        spacebg: "#070a13",
        panelbg: "#111827",
        plasma: "#22d3ee",
        kyber: "#38bdf8",
      },
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "-apple-system", "BlinkMacSystemFont", "sans-serif"],
      },
    },
  },
  plugins: [],
};

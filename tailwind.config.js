/**
 * Build do CSS utilitário do Tailwind (substitui o Play CDN, que é só para dev).
 *
 * Como reconstruir (gera static/css/tailwind.css com APENAS as classes usadas):
 *   npx -y tailwindcss@3 -c tailwind.config.js \
 *     -i static/css/tailwind-src.css -o static/css/tailwind.css --minify
 *
 * O resultado é commitado e servido como estático — nenhum build roda na Render.
 * Refaça este comando sempre que adicionar classes utilitárias novas nos
 * templates ou no JS.
 */
module.exports = {
  content: ['./templates/**/*.html', './static/js/**/*.js'],
  darkMode: 'class',
  // Classes que o JS liga/desliga dinamicamente (garantia extra além do scan).
  safelist: ['hidden', 'flex', 'opacity-50', 'cursor-not-allowed'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Hanken Grotesk"', 'system-ui', 'sans-serif'],
        display: ['Newsreader', 'Georgia', 'serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      colors: {
        primary: {
          100: '#c3d8f5',
          300: '#9bc4ff',
          500: '#6aa6ff',
          700: '#3e6fb0',
          900: '#11161f',
        },
        cream: '#efe4d6',
      },
    },
  },
};

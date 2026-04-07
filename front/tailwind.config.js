/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{ts,html}'],
  theme: {
    extend: {
      colors: {
        sidebar: {
          bg: '#1a1f36',
          hover: '#252b48',
          active: '#2563eb',
          text: '#94a3b8',
          'text-active': '#ffffff',
        },
        primary: {
          DEFAULT: '#2563eb',
          hover: '#1d4ed8',
        },
        success: '#16a34a',
        warning: '#eab308',
        danger: '#dc2626',
        info: '#0ea5e9',
      },
      fontFamily: {
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'sans-serif',
        ],
        mono: ['SF Mono', 'Cascadia Code', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
};

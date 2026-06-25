import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { VitePWA } from 'vite-plugin-pwa'
import { execSync } from 'node:child_process'

let commit = 'dev'
try { commit = execSync('git rev-parse --short HEAD').toString().trim() } catch { /* sin git */ }
const commitMeta = {
  name: 'commit-meta',
  transformIndexHtml (html) { return html.replace('</head>', `  <meta name="commit" content="${commit}" />\n  </head>`) },
}

export default defineConfig({
  base: '/',
  plugins: [
    vue(),
    commitMeta,
    VitePWA({
      registerType: 'autoUpdate',
      includeAssets: ['icon.svg', 'icon-192.png', 'icon-512.png', 'icon-maskable-512.png', 'og.jpg', 'robots.txt', 'sitemap.xml'],
      manifest: {
        name: 'Dotrino Vault — tu certificador personal',
        short_name: 'Dotrino Vault',
        description: 'Sé tu propia autoridad: custodia tu llave maestra y certifica tus dispositivos sin una autoridad central. Self-hosted, sin rastreo.',
        lang: 'es',
        start_url: '/',
        scope: '/',
        display: 'standalone',
        background_color: '#0b1220',
        theme_color: '#0b1220',
        launch_handler: { client_mode: 'focus-existing' },
        icons: [
          { src: 'icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
          { src: 'icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
          { src: 'icon-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
        ],
      },
      workbox: { globPatterns: ['**/*.{js,css,html,svg,png,woff2}'], navigateFallback: null, cleanupOutdatedCaches: true, skipWaiting: true, clientsClaim: true },
    }),
  ],
})

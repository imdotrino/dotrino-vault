import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { VitePWA } from 'vite-plugin-pwa'
import { execSync } from 'node:child_process'
import { copyFileSync, mkdirSync } from 'node:fs'

let commit = 'dev'
try { commit = execSync('git rev-parse --short HEAD').toString().trim() } catch { /* sin git */ }
const commitMeta = {
  name: 'commit-meta',
  transformIndexHtml (html) { return html.replace('</head>', `  <meta name="commit" content="${commit}" />\n  </head>`) },
}

// GitHub Pages no sabe de rutas de una SPA. Tres capas:
//  · `d/index.html` — la ruta CORTA a la que apunta el QR de hoy (`/d#v=…`). Es corta
//    a propósito: dentro de un QR cada carácter se paga en módulos, y los módulos son
//    filas y columnas de terminal (`lib/src/invite.js`).
//  · `dispositivos/index.html` — la ruta larga de siempre (`/dispositivos#vault=…`),
//    la que la gente ya tiene guardada. Sin esto la página se veía igual pero respondía
//    **404**, y un 404 en la puerta de entrada del emparejamiento es pedir problemas
//    (cachés, navegadores embebidos, previsualizaciones de enlace).
//  · `404.html` — red de seguridad para cualquier otra ruta: Pages lo devuelve y la app
//    enruta en el cliente.
const spaFallback = {
  name: 'spa-404',
  closeBundle () {
    try { copyFileSync('dist/index.html', 'dist/404.html') } catch (_) {}
    for (const ruta of ['dispositivos', 'd']) {
      try {
        mkdirSync('dist/' + ruta, { recursive: true })
        copyFileSync('dist/index.html', `dist/${ruta}/index.html`)
      } catch (_) {}
    }
  },
}

export default defineConfig({
  base: '/',
  plugins: [
    vue(),
    commitMeta,
    spaFallback,
    VitePWA({
      registerType: 'autoUpdate',
      injectRegister: false,
      includeAssets: ['icon.svg', 'icon-192.png', 'icon-512.png', 'icon-maskable-512.png', 'og.jpg', 'robots.txt', 'sitemap.xml'],
      manifest: {
        name: 'Dotrino Vault — toda tu información en un solo lugar',
        short_name: 'Dotrino Vault',
        description: 'Guarda toda tu información en una bóveda dentro de tu propia computadora, no en la nube de una empresa. Privada, segura y tuya.',
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
      workbox: { globPatterns: ['**/*.{js,css,html,svg,png,woff2}'], navigateFallback: '/index.html', cleanupOutdatedCaches: true, skipWaiting: true, clientsClaim: true },
    }),
  ],
})

# Dockerfile na raiz para EasyPanel
FROM node:18-alpine

WORKDIR /app

# Copiar package files do server
COPY server/package*.json ./

# Instalar dependências
RUN npm install --production

# Copiar código do servidor
COPY server/ ./

# Copiar frontend (public) - um nível acima do app
COPY public/ /public/

# Expor porta
EXPOSE 4000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4000/api/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Comando de start
CMD ["node", "server.js"]


# Temel imaj
FROM node:20

# Uygulama dizini
WORKDIR /app

# Bağımlılıkları kopyala
COPY package*.json ./
RUN npm install

# Uygulama dosyaları
COPY . .

# Build (eğer TypeScript ise)
RUN npm run build

# Uygulama başlat
CMD ["node", "dist/main"]

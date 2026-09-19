FROM node:20-alpine

RUN apk add --no-cache tzdata
ENV TZ=America/Lima

WORKDIR /app

# Copiar manifiestos de dependencias
COPY package*.json ./

# Instalar dependencias de producción
RUN npm install --omit=dev

# Copiar código fuente del backend
COPY . .

# Puerto del servicio backend
EXPOSE 3008

CMD ["node", "index.js"]

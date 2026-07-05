FROM php:8.2-apache

RUN apt-get update && apt-get install -y \
    git \
    unzip \
    libpng-dev \
    libjpeg62-turbo-dev \
    libfreetype6-dev \
    libzip-dev \
    default-mysql-client

RUN docker-php-ext-configure gd --with-freetype --with-jpeg

RUN docker-php-ext-install mysqli pdo pdo_mysql gd zip

RUN a2enmod rewrite

WORKDIR /var/www/html

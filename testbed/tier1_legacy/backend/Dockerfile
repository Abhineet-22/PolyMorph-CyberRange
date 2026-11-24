FROM php:8.1-apache

# ── Install PHP extensions ─────────────────────────────────────────────────────
# exif: required for exif_imagetype() magic-byte check in upload.php
RUN docker-php-ext-install exif

# ── Enable Apache modules ──────────────────────────────────────────────────────
RUN a2enmod rewrite

# ── Copy application source into document root ─────────────────────────────────
COPY . /var/www/html/

# ── Create uploads directory with world-write permissions ─────────────────────
# chmod 777 is intentionally insecure for lab demonstration purposes.
RUN mkdir -p /var/www/html/uploads && chmod 777 /var/www/html/uploads

# ── INTENTIONALLY VULNERABLE: Misconfigured FilesMatch for Vector 3 ───────────
# The regex below lacks a '$' anchor, so 'avatar.php.jpg' matches \.php
# and Apache passes it to mod_php for execution (double-extension bypass).
RUN printf '\n<FilesMatch "\\.php">\n    SetHandler application/x-httpd-php\n</FilesMatch>\n' \
    >> /etc/apache2/apache2.conf

# ── Allow .htaccess overrides (needed for Vector 2 AddType trick) ─────────────
RUN sed -i 's/AllowOverride None/AllowOverride All/g' \
        /etc/apache2/apache2.conf \
    ; sed -i 's/AllowOverride None/AllowOverride All/g' \
        /etc/apache2/sites-available/000-default.conf || true

# ── Set ServerName to suppress warning ────────────────────────────────────────
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

EXPOSE 80

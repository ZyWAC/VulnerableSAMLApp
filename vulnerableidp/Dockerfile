FROM php:8.1-apache

# Install dependencies
RUN apt-get update -y && apt-get install --fix-missing -y \
    wget \
    unzip \
    libxml2-dev \
    && docker-php-ext-install xml \
    && a2enmod rewrite \
    && rm -rf /var/lib/apt/lists/*

# Download and install SimpleSAMLphp 1.19.8 (last 1.x release, compatible with existing config)
RUN wget -q https://github.com/simplesamlphp/simplesamlphp/releases/download/v1.19.8/simplesamlphp-1.19.8.tar.gz \
    && tar xzf simplesamlphp-1.19.8.tar.gz \
    && mv simplesamlphp-1.19.8 /var/simplesamlphp \
    && rm simplesamlphp-1.19.8.tar.gz

# Enable SAML 2.0 IdP and exampleauth module
RUN touch /var/simplesamlphp/modules/exampleauth/enable \
    && rm -f /var/simplesamlphp/modules/exampleauth/default-disable
RUN sed -ie "s/'enable.saml20-idp' => false/'enable.saml20-idp' => true/g" /var/simplesamlphp/config/config.php
# Allow plain HTTP (no HTTPS) for local/CTF usage
RUN sed -ie "s/'session.cookie.secure' => true/'session.cookie.secure' => false/g" /var/simplesamlphp/config/config.php
# Enable exampleauth module in config
RUN sed -ie "s/'exampleauth' => false/'exampleauth' => true/g" /var/simplesamlphp/config/config.php
# Set baseurlpath to match Apache alias
RUN sed -ie "s|'baseurlpath' => 'simplesaml/'|'baseurlpath' => 'simplesamlphp/'|g" /var/simplesamlphp/config/config.php
# Fix SameSite cookie for plain HTTP (SameSite=None requires Secure flag / HTTPS)
RUN sed -ie "s|\\\\SimpleSAML\\\\Utils\\\\HTTP::canSetSameSiteNone() ? 'None' : null|'Lax'|g" /var/simplesamlphp/config/config.php

# Set up Apache alias for SimpleSAMLphp
RUN echo 'Alias /simplesamlphp /var/simplesamlphp/www' > /etc/apache2/conf-available/simplesamlphp.conf \
    && echo '<Directory /var/simplesamlphp/www>' >> /etc/apache2/conf-available/simplesamlphp.conf \
    && echo '    Require all granted' >> /etc/apache2/conf-available/simplesamlphp.conf \
    && echo '</Directory>' >> /etc/apache2/conf-available/simplesamlphp.conf \
    && a2enconf simplesamlphp

# Copy configuration files
ADD authsources.php /var/simplesamlphp/config/
ADD saml20-idp-hosted.php /var/simplesamlphp/metadata/
ADD saml20-sp-remote.php /var/simplesamlphp/metadata/
ADD yogi-idp.local.crt /var/simplesamlphp/cert/
ADD yogi-idp.local.pem /var/simplesamlphp/cert/
ADD loginuserpass.php /var/simplesamlphp/modules/core/templates/
ADD loginuserpass.twig /var/simplesamlphp/modules/core/templates/
# Override the default .tpl.php template with our custom Jellystone IDP template
COPY loginuserpass.php /var/simplesamlphp/modules/core/templates/loginuserpass.tpl.php
ADD welcome.png /var/simplesamlphp/www/resources/

EXPOSE 80

# Start the web service
CMD ["apache2-foreground"]

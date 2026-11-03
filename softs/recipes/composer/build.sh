cd "$SRC"
F="$(fetch "https://getcomposer.org/download/$VERSION/composer.phar" \
      "$(curl -fsSL "https://getcomposer.org/download/$VERSION/composer.phar.sha256sum" | awk '{print $1}')")"
install -D -m 0755 "$F" "$DEST$PREFIX/bin/composer"

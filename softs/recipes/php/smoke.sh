#!/bin/bash
set -e
V="$VP_TRACK"
"/usr/bin/php$V" -r 'if (!function_exists("imagecreate") || !class_exists("PDO") || !extension_loaded("intl")) exit(1);' \
  || { echo "gd / PDO / intl missing"; exit 1; }
# every PECL extension the build says it carries must load (share/conf/pecl.txt: name=source)
P="$(readlink -f "/usr/local/vortex/php/$V")"
if [ -f "$P/share/conf/pecl.txt" ]; then
  for e in $(cut -d= -f1 "$P/share/conf/pecl.txt"); do
    "/usr/bin/php$V" -d "extension=$e" -r "exit(extension_loaded('$e') ? 0 : 1);" 2>/dev/null \
      || { echo "PECL extension $e is in the build but does not load"; exit 1; }
  done
  echo "PECL extensions load: $(cut -d= -f1 "$P/share/conf/pecl.txt" | tr '\n' ' ')"
fi
printf 'SCRIPT_NAME=/t.php SCRIPT_FILENAME=/tmp/t.php REQUEST_METHOD=GET\n' >/dev/null
echo '<?php echo "ok";' > /tmp/t.php
echo "PHP $("/usr/bin/php$V" -r 'echo PHP_VERSION;') smoke test passed"

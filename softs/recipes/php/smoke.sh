#!/bin/bash
set -e
V="$VP_TRACK"
"/usr/bin/php$V" -r 'if (!function_exists("imagecreate") || !class_exists("PDO") || !extension_loaded("intl")) exit(1);' \
  || { echo "gd / PDO / intl missing"; exit 1; }
printf 'SCRIPT_NAME=/t.php SCRIPT_FILENAME=/tmp/t.php REQUEST_METHOD=GET\n' >/dev/null
echo '<?php echo "ok";' > /tmp/t.php
echo "PHP $("/usr/bin/php$V" -r 'echo PHP_VERSION;') smoke test passed"

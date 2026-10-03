#!/data/data/com.termux/files/usr/bin/bash
# REVIVE CODEXRC SOLO AL ARRANCAR EL TELEFONO (v0.62.7)
#
# Requisito UNA sola vez: instalar la app "Termux:Boot" desde F-Droid
#   https://f-droid.org/en/packages/com.termux.boot/
# y abrirla una vez. Luego:
#   bash boot_install.sh
#
# Que hace: crea ~/.termux/boot/00-codexrc.sh para que cada vez que
# Android reinicie (o mate Termux y el sistema lo reanime), el server
# localhost:8000 arranque solo, con wake-lock y auto-resurreccion.

mkdir -p "$HOME/.termux/boot"

cat > "$HOME/.termux/boot/00-codexrc.sh" <<'BOOT'
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock 2>/dev/null
cd "$HOME/codexRC" || cd "$HOME/CodexRC" || exit 1
bash auto_update.sh >> "$HOME/codexrc_boot.log" 2>&1 &
BOOT

chmod +x "$HOME/.termux/boot/00-codexrc.sh"
echo "OK: boot instalado. Al reiniciar el telefono, CodexRC se levanta solo."
echo "Verificalo reiniciando el telefono y abriendo localhost:8000."

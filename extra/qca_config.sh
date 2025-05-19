echo "Enabling SPI in config.txt"
sudo sed -i '/^dtparam=spi=on/d' /boot/firmware/config.txt
echo "dtparam=spi=on" | sudo tee -a /boot/config.txt

echo "Enabling SPI via raspi-config"
sudo raspi-config nonint do_spi 0

echo "Adding QCA7000 overlay to config.txt"
sudo sed -i '/^dtoverlay=qca7000/d' /boot/firmware/config.txt
echo "dtoverlay=qca7000" | sudo tee -a /boot/firmware/config.txt
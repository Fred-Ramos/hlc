echo "Installing libffi-dev"
sudo apt install libffi-dev

echo "Installing poetry"
sudo apt install pipx
pipx install poetry
pipx ensurepath

echo "Installing java"
sudo apt install openjdk-17-jre -y

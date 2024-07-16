#!/bin/bash
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install nginx -y
git clone https://github.com/Sukhilnair/Web_for_test.git
sudo cp ./Web_for_test/index.html /var/www/html/index.html
sudo systemctl restart nginx
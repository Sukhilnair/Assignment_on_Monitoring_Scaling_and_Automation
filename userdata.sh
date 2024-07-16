#!/bin/bash
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install nginx -y
sudo apt-get install wget -y
wget https://sukhilmybucket2.s3.ap-northeast-2.amazonaws.com/webstatic.zip
unzip webstatic.zip
sudo cp ./webstatic/* /var/www/html/*
sudo systemctl restart nginx
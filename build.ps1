docker build -t "spectrum-app" .
cd waf
docker build -t "firewall" .
cd ../
docker-compose up
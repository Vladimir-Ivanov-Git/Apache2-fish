# Important information:
***This project is created only for education process and can not be used for 
law violation or personal gain. The author of this project is not responsible for any possible harm caused by the materials of this project.***

# Важная информация:
***Данный проект создан исключительно в образовательных целях, и не может быть использован в целях нарушающих законодательство, в корыстных целях или для получения какой-либо выгоды как для самого автора так и лиц его использующих.
Автор данного проекта не несет ответственности за любой возможный вред, причиненный материалами данного проекта.***

# Apache2-fish
Setup Apache2 for fishing proxy

```
root@kali:/git/Apache2-fish# ./setup_apache2_proxy.py -h
usage: setup_apache2_proxy.py [-h] [-u URL] [-C COUNTRY] [-S STATE]
                              [-L LOCALITY] [-O ORGANIZATION]
                              [-U ORGANIZATION_UNIT] [-r REPLACE] [-b BEEF]
                              [-c HTTP_CONFIG] [-s HTTPS_CONFIG] [-E] [-D]

Setup Apache2 fishing proxy

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Set URL for proxy (example: "http://test.com")
  -C COUNTRY, --country COUNTRY
                        Set Country for SSL cert (default: RU)
  -S STATE, --state STATE
                        Set State for SSL cert (default: Moscow)
  -L LOCALITY, --locality LOCALITY
                        Set Locality for SSL cert (default: Moscow)
  -O ORGANIZATION, --organization ORGANIZATION
                        Set Organization for SSL cert
  -U ORGANIZATION_UNIT, --organization_unit ORGANIZATION_UNIT
                        Set Organization unit for SSL cert (default: IT)
  -r REPLACE, --replace REPLACE
                        Find and replace string in response (example:
                        "s|foo|bar|ni")
  -b BEEF, --beef BEEF  Set path to BeeF script (example:
                        "http://192.168.0.1/beef.js")
  -c HTTP_CONFIG, --http_config HTTP_CONFIG
                        Set path to Apache2 http site config (default:
                        /etc/apache2/sites-available/000-default.conf)
  -s HTTPS_CONFIG, --https_config HTTPS_CONFIG
                        Set path to Apache2 https site config (default:
                        /etc/apache2/sites-available/default-ssl.conf)
  -E, --erase_conf      Erase Apache2 config files
  -D, --delete_log      Delete Apache2 log files
  ```

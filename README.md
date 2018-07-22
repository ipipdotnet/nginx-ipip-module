# nginx-ipip-module
Nginx ipip module support datx format 
# IPIP.net
    Free offline database download https://www.ipip.net/free_download/
    Advanced paid version
        [English](https://en.ipip.net/product/ip.html) [中文](https://www.ipip.net/product/ip.html)

# Installing
#### download (nginx 1.12.1 +)
    wget http://nginx.org/download/nginx-VERSION.tar.gz
    tar zxvf nginx-VERSION.tar.gz
#### download nginx-ipip-module    
    git clone https://github.com/ipipdotnet/nginx-ipip-module

#### compile
    cd nginx-VERSION
    ./configure --with-compat --add-dynamic-module=../nginx-ipip-module
    make modules .
    make install

# Example
    http {

        # Specify the data file path
        ipip_db /root/ipip.datx 60m; # 60 minute auto reload db file

        server {
            listen       80;
            server_name  localhost;

            # Specifies the IP address to parse, Default $remote_addr
            ipip_parse_ip $http_x_forwarded_for;

            location / {
                if ($ipip_country_code = HK) {
                    return 403;
                }

                if ($ipip_country_code ~* "(MO|TW)") {
                    return 403;
                }

                if ($ipip_country_code !~ CN) {
                    return 403;
                }                

                add_header ip $http_x_forwarded_for;
                add_header country_code $ipip_country_code;
                add_header country $ipip_country_name;
                add_header province $ipip_region_name;
                add_header city $ipip_city_name;
                add_header owner $ipip_owner_domain;
                add_header isp $ipip_isp_domain;
                add_header latitude $ipip_latitude;
                add_header longitude $ipip_longitude;
            
                root   html;
                index  index.html index.htm;
            }
        }    
    }

# Directive
    ipip_db /path/db/file 60m; Specify the database file path and automatic update time interval
    ipip_parse_ip $remote_addr; Specifies the variable that gets the IP

# Variables
#### Buying a paid database gives you more data
    $ipip_continent_code
    $ipip_country_name
    $ipip_country_code
    $ipip_region_name
    $ipip_city_name
    $ipip_owner_domain
    $ipip_isp_domain
    $ipip_latitude
    $ipip_longitude
    $ipip_timezone
    $ipip_utc_offset
    $ipip_china_admin_code
    $ipip_idd_code
    $ipip_idc
    $ipip_base_station
    $ipip_anycast

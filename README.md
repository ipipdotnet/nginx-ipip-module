# nginx-ipip-module
Nginx ipip module support datx format 

# Installing
#### download nginx
    wget http://nginx.org/download/nginx-VERSION.tar.gz
    tar zxvf nginx-VERSION.tar.gz
#### download nginx-ipip-module    
    git clone https://github.com/ipipdotnet/nginx-ipip-module

#### compile
    cd nginx-VERSION
    ./configure --with-compat --add-dynamic-module=../nginx-ipip-module
    make modules .
    make install

# Variables
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
#!/bin/bash
#
#a10 to illumio sync
version="0.0.2"
#
#Licensed under the Apache License, Version 2.0 (the "License"); you may not
#use this file except in compliance with the License. You may obtain a copy of
#the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#License for the specific language governing permissions and limitations under
#the License.
#
#Reference: https://acos.docs.a10networks.com/axapi/521/index.html
#
usage(){
    cat << EOF
a10-illumio-sync.sh

jq is required to parse results
https://stedolan.github.io/jq/

usage: ./a10-illumio-sync.sh [options]

options:
    --get-a10-vips          get a10 lb vips
    --get-a10-acls          get a10 lb acls
    --get-a10-snat-pools    get a10 lb snat pools
    --sync-vips             creates illumio unmanaged workloads from a10 lb vips
    --sync-rules            creates/updates a10 vip acls from illumio rules
    --sync-snat-pools       creates/updates illumio ip lists from a10 lb snat pools
EOF
}

get_jq_version(){
    jq_version=$(jq --version)
    if [ $(echo $?) -ne 0 ]; then
        echo "jq application not found. jq is a command line JSON processor and is used to process and filter JSON inputs."
        echo "Reference: https://stedolan.github.io/jq/"
        echo "Please install jq, i.e. yum install jq"
        exit 1
    fi
}

get_version(){
    echo "a10-illumio-sync v"$version
}

get_config_yml(){
    source $BASEDIR/.illumio_config.yml >/dev/null 2>&1 || get_illumio_variables
    source $BASEDIR/.a10_config.yml >/dev/null 2>&1 || get_a10_variables
}

get_illumio_variables(){
    echo ""
    read -p "Enter illumio PCE domain: " ILLUMIO_PCE_DOMAIN
    read -p "Enter illumio PCE port: " ILLUMIO_PCE_PORT
    read -p "Enter illumio PCE organization ID: " ILLUMIO_PCE_ORG_ID
    read -p "Enter illumio PCE API username: " ILLUMIO_PCE_API_USERNAME
    echo -n "Enter illumio PCE API secret: " && read -s ILLUMIO_PCE_API_SECRET && echo ""
    cat << EOF > $BASEDIR/.illumio_config.yml
export ILLUMIO_PCE_DOMAIN=$ILLUMIO_PCE_DOMAIN
export ILLUMIO_PCE_PORT=$ILLUMIO_PCE_PORT
export ILLUMIO_PCE_ORG_ID=$ILLUMIO_PCE_ORG_ID
export ILLUMIO_PCE_API_USERNAME=$ILLUMIO_PCE_API_USERNAME
export ILLUMIO_PCE_API_SECRET=$ILLUMIO_PCE_API_SECRET
EOF
}

get_a10_variables(){
    read -p "Enter a10 appliance IP or hostname: " A10_HOST
    read -p "Enter a10 username: " A10_USERNAME
    echo -n "Enter a10 password: " && read -s A10_PASSWORD && echo ""
    echo ""
    cat << EOF > $BASEDIR/.a10_config.yml
export A10_HOST=$A10_HOST
export A10_USERNAME=$A10_USERNAME
export A10_PASSWORD=$A10_PASSWORD
EOF
}

get_a10_authresponse_signature(){
    A10_AUTHRESPONSE_SIGNATURE=$(curl -s -k https://$A10_HOST/axapi/v3/auth -H "Content-Type:application/json" -d '{"credentials": {"username": "'$A10_USERNAME'","'password'": "'$A10_PASSWORD'"}}' | jq -r .authresponse.signature)
}

get_a10_vips(){
    get_a10_authresponse_signature
    A10_VIRTUAL_SERVERS=($(curl -s -k -H "Authorization: A10 $A10_AUTHRESPONSE_SIGNATURE" https://$A10_HOST/axapi/v3/slb/virtual-server | jq -r '."virtual-server-list"[]|.name,."ip-address"'))
    A10_VIRTUAL_SERVERS_GET_FILENAME="A10-VIRTUAL-SERVERS-GET-$(date +%Y.%m.%dT%H.%M.%S).log"
    for i in "${!A10_VIRTUAL_SERVERS[@]}"; do
        if [[ $((i % 2)) -eq 0 ]]; then
            echo -n "${A10_VIRTUAL_SERVERS[$i]}," >> $A10_VIRTUAL_SERVERS_GET_FILENAME
        else echo "${A10_VIRTUAL_SERVERS[$i]}" >> $A10_VIRTUAL_SERVERS_GET_FILENAME
        fi
    done
    echo -e "\nFound A10 VIPS > $A10_VIRTUAL_SERVERS_GET_FILENAME"
}

get_a10_snat_pools(){
    get_a10_authresponse_signature
    A10_SNATS=($(curl -s -k -H "Authorization: A10 $A10_AUTHRESPONSE_SIGNATURE" https://$A10_HOST/axapi/v3/ip/nat | jq -r '.nat."pool-list"[]|."pool-name",."start-address",."end-address"'))
    A10_SNATS_GET_FILENAME="A10-SNATS-GET-$(date +%Y.%m.%dT%H.%M.%S).log"
    for i in "${!A10_SNATS[@]}"; do
        if [[ $((((i+1)) % 3)) -eq 0 ]]; then
            echo "${A10_SNATS[$i]}" >> $A10_SNATS_GET_FILENAME
        else
            echo -n "${A10_SNATS[$i]}," >> $A10_SNATS_GET_FILENAME
        fi
    done
    echo -e "\nFound A10 Source NAT Pools > $A10_SNATS_GET_FILENAME"
}

get_a10_acls(){
    get_a10_authresponse_signature
    A10_ACLS=($(curl -s -k -H "Authorization: A10 $A10_AUTHRESPONSE_SIGNATURE" https://$A10_HOST/axapi/v3/access-list | jq -r '."access-list"'))
    A10_ACLS_GET_FILENAME="A10-ACLS-GET-$(date +%Y.%m.%dT%H.%M.%S).log"
    echo ${A10_ACLS[@]} > $A10_ACLS_GET_FILENAME
    echo -e "\nFound A10 ACLs > $A10_ACLS_GET_FILENAME"
}

sync_vips(){
    get_a10_vips
    A10_VIRTUAL_SERVERS_GET=$(cat $A10_VIRTUAL_SERVERS_GET_FILENAME)
    for A10_VIRTUAL_SERVER_GET in $A10_VIRTUAL_SERVERS_GET; do
        A10_VIRTUAL_SERVER_NAME=$(echo $A10_VIRTUAL_SERVER_GET | cut -d, -f1)
        A10_VIRTUAL_SERVER_IP=$(echo $A10_VIRTUAL_SERVER_GET | cut -d, -f2)
        #get workload by ip address
        WORKLOAD=$(curl -k -s "https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2/orgs/$ILLUMIO_PCE_ORG_ID/workloads?ip_address=$A10_VIRTUAL_SERVER_IP" | jq -c -r .[])
        #if no workload, create unmanaged workload
        if [ ! -n "$WORKLOAD" ]; then
            echo -e "\nUnmanaged workload created:"
            body='{"name":"'$A10_VIRTUAL_SERVER_NAME'","description":"Created by A10 illumio sync tool","hostname":"'$A10_VIRTUAL_SERVER_NAME'","interfaces":[{"address":"'$A10_VIRTUAL_SERVER_IP'","name":"umw0"}]}'
            curl -k -X POST "https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2/orgs/$ILLUMIO_PCE_ORG_ID/workloads" -H 'content-type: application/json' --data "$body"
            echo ""
        fi
    done
}

sync_rules(){
    sync_vips
    A10_VIRTUAL_SERVERS_GET=$(cat $A10_VIRTUAL_SERVERS_GET_FILENAME)
    for A10_VIRTUAL_SERVER_GET in $A10_VIRTUAL_SERVERS_GET; do
        A10_VIRTUAL_SERVER_NAME=$(echo $A10_VIRTUAL_SERVER_GET | cut -d, -f1)
        A10_VIRTUAL_SERVER_IP=$(echo $A10_VIRTUAL_SERVER_GET | cut -d, -f2)
        #get workload href by ip address
        WORKLOAD_HREF=$(curl -k -s "https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2/orgs/$ILLUMIO_PCE_ORG_ID/workloads?ip_address=$A10_VIRTUAL_SERVER_IP" | jq -c -r .[].href)
        ILLUMIO_SEC_RULES_HREFS=$(curl -k -s "https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2/orgs/$ILLUMIO_PCE_ORG_ID/sec_policy/active/rule_search" -X POST -H 'content-type: application/json' --data-raw '{"resolve_actors":true,"providers":[{"workload":{"href":"'$WORKLOAD_HREF'"}}]}' | jq -r .[].href)
        #declare vip acl ips array
        ## change to multi-dem array, with ip and netmask
        ILLUMIO_SOURCE_IPS=()
        #for each rule, get source ips
        for ILLUMIO_SEC_RULE_HREF in $ILLUMIO_SEC_RULES_HREFS; do
            #rules with labels
            ILLUMIO_SEC_RULE_CONSUMERS_LABELS_HREFS=$(curl -k -s "https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2$ILLUMIO_SEC_RULE_HREF" | jq -c '.consumers[].label.href | select(. != null)')
            ILLUMIO_SEC_RULE_CONSUMERS_IP_LISTS_HREFS=$(curl -k -s "https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2$ILLUMIO_SEC_RULE_HREF" | jq -r -c '.consumers[].ip_list.href | select(. != null)')
            #if rule contains labels
            #todo:account for label or statements (multiple labels)
            if [ ! -z "$ILLUMIO_SEC_RULE_CONSUMERS_LABELS_HREFS" ]; then
                #add encoded brackets for list of labels
                ILLUMIO_SEC_RULE_CONSUMERS_LABELS_HREFS="%5B%5B$ILLUMIO_SEC_RULE_CONSUMERS_LABELS_HREFS%5D%5D"
                #replace white space with commas
                ILLUMIO_SEC_RULE_CONSUMERS_LABELS_HREFS=$(echo $ILLUMIO_SEC_RULE_CONSUMERS_LABELS_HREFS | tr -s ' ' | tr ' ' ',')
                #get workload ips by label, append to a10 vip acl ip array
                #exclude link local
                #exclude ipv6
                ILLUMIO_SOURCE_IPS+=($(curl -k -s "https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2/orgs/$ILLUMIO_PCE_ORG_ID/workloads?online=true&labels=$ILLUMIO_SEC_RULE_CONSUMERS_LABELS_HREFS" | jq -r '.[].interfaces[] | select(.network_detection_mode != "link_local") | .address'))
            fi
            #if rule contains ip lists
            #todo:account for ip list exclusions
            #todo:account for ip ranges? logic for from/to, if to null, if to calculate ips
            #todo:if fqdn, skip, not supported in a10
            if [ ! -z "$ILLUMIO_SEC_RULE_CONSUMERS_IP_LISTS_HREFS" ]; then
                for ILLUMIO_SEC_RULE_CONSUMER_IP_LIST_HREF in $ILLUMIO_SEC_RULE_CONSUMERS_IP_LISTS_HREFS; do
                    ILLUMIO_SOURCE_IPS+=($(curl -k -s "https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2$ILLUMIO_SEC_RULE_CONSUMER_IP_LIST_HREF" | jq -r .ip_ranges[].from_ip))
                done
            fi
            #label groups
        done
        #echo "${ILLUMIO_SOURCE_IPS[*]}"
        #create/update a10 security object group
        BODY_RULE_IPS=""
        for i in "${!ILLUMIO_SOURCE_IPS[@]}"; do
            ILLUMIO_SOURCE_IP="${ILLUMIO_SOURCE_IPS[$i]}"
            #if subnet cidr
            if [[ $ILLUMIO_SOURCE_IP == *"/"* ]];then
                ILLUMIO_SOURCE_IP_SUBNET=$(echo $ILLUMIO_SOURCE_IP | cut -d/ -f1)
                ILLUMIO_SOURCE_IP_SUBNET_MASK=$(echo $ILLUMIO_SOURCE_IP | cut -d/ -f2)
                BODY_RULE_IPS+='{"seq-num":'$(($i+1))',"subnet":"'$ILLUMIO_SOURCE_IP_SUBNET'","rev-subnet-mask":"/'$ILLUMIO_SOURCE_IP_SUBNET_MASK'"}'
            else
                BODY_RULE_IPS+='{"seq-num":'$(($i+1))',"subnet":"'$ILLUMIO_SOURCE_IP'","rev-subnet-mask":"0.0.0.0"}'
            fi
            #if not last object, append comma
            if [[ "$(($i+1))" != "${#ILLUMIO_SOURCE_IPS[@]}" ]]; then
                BODY_RULE_IPS+=","
            fi
        done
        #create/update a10 network object group with illumio workload ips
        GET_A10_NETWORK_OBJECT_GROUP_RESPONSE=$(curl -s -k -H "Authorization: A10 $A10_AUTHRESPONSE_SIGNATURE" https://$A10_HOST/axapi/v3/object-group/network/ilo-$A10_VIRTUAL_SERVER_NAME --write-out "%{http_code}\n" -o /dev/null)
        if [[ ! "$GET_A10_NETWORK_OBJECT_GROUP_RESPONSE" == "200" ]]; then
            #create a10 network object group
            body='{"network": {"net-name": "ilo-'$A10_VIRTUAL_SERVER_NAME'","rules": ['$BODY_RULE_IPS']}}'
            curl -s -k -H "Authorization: A10 $A10_AUTHRESPONSE_SIGNATURE" https://$A10_HOST/axapi/v3/object-group/network -X POST -H 'content-type: application/json' --data "$body" -o /dev/null
        else
            #update a10 network object group
            body='{"network": {"rules": ['$BODY_RULE_IPS']}}'
            curl -s -k -H "Authorization: A10 $A10_AUTHRESPONSE_SIGNATURE" https://$A10_HOST/axapi/v3/object-group/network/ilo-$A10_VIRTUAL_SERVER_NAME -X PUT -H 'content-type: application/json' --data "$body" -o /dev/null
        fi        
        #create/update a10 acl, apply security object group
        #16 char name limit
        #NOTE:ilo prefix
        GET_A10_IPV4_ACCESS_LIST_RESPONSE=$(curl -s -k -H "Authorization: A10 $A10_AUTHRESPONSE_SIGNATURE" https://$A10_HOST/axapi/v3/ip/access-list/${A10_VIRTUAL_SERVER_NAME:0:16} --write-out "%{http_code}\n" -o /dev/null)
        if [[ ! "$GET_A10_IPV4_ACCESS_LIST_RESPONSE" == "200" ]]; then
            #create a10 ipv4 access list, add source network object group
            body='{"access-list": {"name":"'${A10_VIRTUAL_SERVER_NAME:0:16}'","rules": [{"seq-num":1,"action":"permit","ip":1,"src-object-group":"ilo-'$A10_VIRTUAL_SERVER_NAME'","dst-any":1}]}}'
            curl -s -k -H "Authorization: A10 $A10_AUTHRESPONSE_SIGNATURE" https://$A10_HOST/axapi/v3/ip/access-list -X POST -H 'content-type: application/json' --data "$body" -o /dev/null
        else
            #update a10 ipv4 access list
            body='{"access-list": {"rules": [{"seq-num":1,"action":"permit","ip":1,"src-object-group":"ilo-'$A10_VIRTUAL_SERVER_NAME'","dst-any":1}]}}'
            curl -s -k -H "Authorization: A10 $A10_AUTHRESPONSE_SIGNATURE" https://$A10_HOST/axapi/v3/ip/access-list/${A10_VIRTUAL_SERVER_NAME:0:16} -X POST -H 'content-type: application/json' --data "$body" -o /dev/null
        fi
        #apply a10 acl to a10 vip
        GET_A10_VIRTUAL_SERVER_NAME=$(curl -s -k -H "Authorization: A10 $A10_AUTHRESPONSE_SIGNATURE" https://$A10_HOST/axapi/v3/slb/virtual-server/$A10_VIRTUAL_SERVER_NAME/port)
        A10_VIRTUAL_SERVER_NAME_ACL_LIST=$(echo $GET_A10_VIRTUAL_SERVER_NAME | jq -r '."port-list"[]."acl-list"[]."acl-name"' 2> /dev/null)
        if [[ "$A10_VIRTUAL_SERVER_NAME_ACL_LIST" != "${A10_VIRTUAL_SERVER_NAME:0:16}" ]]; then
            UPDATE_A10_VIRTUAL_SERVER_NAME=$(echo $GET_A10_VIRTUAL_SERVER_NAME | jq '."port-list"[]+={"acl-list": [{"acl-name":"'${A10_VIRTUAL_SERVER_NAME:0:16}'"}]}')
            #UPDATE:change vip to variable
            curl -s -k -H "Authorization: A10 $A10_AUTHRESPONSE_SIGNATURE" "https://$A10_HOST/axapi/v3/slb/virtual-server/$A10_VIRTUAL_SERVER_NAME/port" -X PUT -H 'content-type: application/json' --data "$UPDATE_A10_VIRTUAL_SERVER_NAME" -o /dev/null
        fi
    done
}

sync_snat_pools(){
    get_a10_snat_pools
    A10_SNATS_GET=$(cat $A10_SNATS_GET_FILENAME)
    #for each snat pool
    for A10_SNAT_GET in $A10_SNATS_GET; do
        A10_SNAT_POOL_NAME=$(echo $A10_SNAT_GET | cut -d, -f1)
        A10_SNAT_POOL_START_ADDRESS=$(echo $A10_SNAT_GET | cut -d, -f2)
        A10_SNAT_POOL_END_ADDRESS=$(echo $A10_SNAT_GET | cut -d, -f3)
        #create/update illumio ip list
        GET_ILLUMIO_IP_LIST_HREF=$(curl -s -k "https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2/orgs/$ILLUMIO_PCE_ORG_ID/sec_policy/draft/ip_lists?name=$A10_SNAT_POOL_NAME&description=Created%20by%20A10%20illumio%20sync%20tool" | jq -r .[].href)
        if [[ -n "$GET_ILLUMIO_IP_LIST_HREF" ]];then
            #get
            GET_ILLUMIO_IP_LIST_OBJECT=$(curl -s -k "https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2$GET_ILLUMIO_IP_LIST_HREF")
            GET_ILLUMIO_IP_LIST_OBJECT_FROM_IP=$(echo $GET_ILLUMIO_IP_LIST_OBJECT | jq -r .ip_ranges[].from_ip)
            GET_ILLUMIO_IP_LIST_OBJECT_TO_IP=$(echo $GET_ILLUMIO_IP_LIST_OBJECT | jq -r .ip_ranges[].to_ip)
            #if different
            if [[ "$GET_ILLUMIO_IP_LIST_OBJECT_FROM_IP" != "$A10_SNAT_POOL_START_ADDRESS" ]] && [[ "$GET_ILLUMIO_IP_LIST_OBJECT_TO_IP" != "$A10_SNAT_POOL_END_ADDRESS" ]]; then
                #update/put ip list if different
                echo ""
                echo "Updated illumio IP list with latest A10 snat pool IPs."
                curl -s -k -X PUT "https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2$GET_ILLUMIO_IP_LIST_HREF" -H 'content-type: application/json' --data-raw '{"description":"Created by A10 illumio sync tool","ip_ranges":[{"from_ip":"'$A10_SNAT_POOL_START_ADDRESS'","to_ip":"'$A10_SNAT_POOL_END_ADDRESS'"}]}'
            fi
        else
            #create ip list
            echo ""
            echo "Created illumio IP list:"
            curl -s -k "https://$ILLUMIO_PCE_API_USERNAME:$ILLUMIO_PCE_API_SECRET@$ILLUMIO_PCE_DOMAIN:$ILLUMIO_PCE_PORT/api/v2/orgs/$ILLUMIO_PCE_ORG_ID/sec_policy/draft/ip_lists" -X POST -H 'content-type: application/json' --data-raw '{"name":"'$A10_SNAT_POOL_NAME'","description":"Created by A10 illumio sync tool","ip_ranges":[{"from_ip":"'$A10_SNAT_POOL_START_ADDRESS'","to_ip":"'$A10_SNAT_POOL_END_ADDRESS'"}]}'
        fi
    done
}

#add log entries for each line
#log cleanup, last 100 lines for general log, keep 10 latest get logs

BASEDIR=$(dirname $0)

get_jq_version

get_config_yml

while true
do
    #todo: account for if no argument was provided
    if [ "$1" == "" ]; then
        break
    fi
    case $1 in
        --get-a10-vips)
            get_a10_vips
            exit 0
            ;;
        --get-a10-snat-pools)
            get_a10_snat_pools
            exit 0
            ;;
        --get-a10-acls)
            get_a10_acls
            exit 0
            ;;
        --sync-vips)
            sync_vips
            exit 0
            ;;
        --sync-rules)
            sync_rules
            exit 0
            ;;
        --sync-snat-pools)
            sync_snat_pools
            exit 0
            ;;
        -v|--version)
            get_version
            exit 0
            ;;
        -h|--help)
            usage
            exit 1
            ;;
        -*)
            echo -e "\n$0: ERROR: Unknown option: $1" >&2
            usage
            exit 1
            ;;
        *)
            echo -e "\n$0: ERROR: Unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

exit 0
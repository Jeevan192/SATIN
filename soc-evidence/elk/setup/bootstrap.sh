#!/bin/sh
set -eu

url="http://elasticsearch:9200"
auth="elastic:${ELASTIC_PASSWORD}"

attempt=0
until curl --silent --show-error --fail --user "$auth" "$url/" >/dev/null; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 60 ]; then
        echo "Elasticsearch did not become ready" >&2
        exit 1
    fi
    sleep 2
done

curl --silent --show-error --fail --user "$auth" \
    --request POST "$url/_security/user/kibana_system/_password" \
    --header 'Content-Type: application/json' \
    --data "{\"password\":\"${KIBANA_SYSTEM_PASSWORD}\"}" >/dev/null

curl --silent --show-error --fail --user "$auth" \
    --request PUT "$url/_security/role/logstash_writer" \
    --header 'Content-Type: application/json' \
    --data '{"cluster":["monitor","manage_index_templates"],"indices":[{"names":["soc-events-*"],"privileges":["create_index","create_doc","write"]}]}' >/dev/null

curl --silent --show-error --fail --user "$auth" \
    --request PUT "$url/_security/user/logstash_internal" \
    --header 'Content-Type: application/json' \
    --data "{\"password\":\"${LOGSTASH_PASSWORD}\",\"roles\":[\"logstash_writer\"]}" >/dev/null
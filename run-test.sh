
XML=s3-create-bucket.xml
DATA=$(cat ${XML})

curl -X PUT --insecure -v -H "Host: bucket.s3.amazonws.com" \
     -H "Content-Type: */*" \
     --data-raw "${DATA}" https://localhost:7878

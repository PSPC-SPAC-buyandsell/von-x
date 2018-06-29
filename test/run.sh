DIR=`dirname $0`
docker build -t vonx-test -f "$DIR/Dockerfile" "$DIR/.." || exit 1
docker run --rm  -p 5000:5000 -v vonx-wallet:/home/indy/.indy_client/wallet -ti vonx-test python -m test.testSequence

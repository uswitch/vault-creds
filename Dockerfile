FROM alpine:3.8
RUN apk add --no-cache ca-certificates

ADD bin/vaultcreds /vaultcreds

ENTRYPOINT ["/vaultcreds"]
CMD []

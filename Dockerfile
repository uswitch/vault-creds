FROM alpine:3 as base

RUN apk add -U --no-cache ca-certificates

FROM scratch

ADD bin/vaultcreds /vaultcreds

COPY --chmod=755 --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/vaultcreds"]
CMD []
